use std::{
    any::Any,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Ok, Result, anyhow};
use cgroups::{
    Cgroup, CgroupPid, Controller, DeviceResource,
    cpuset::CpuSetController,
    devices::{DevicePermissions, DeviceType},
    freezer::{FreezerController, FreezerState},
    memory::MemController,
};
use libc::{self, pid_t};
use oci::LinuxResources;
use oci_spec::runtime::{self as oci, Spec};
use protobuf::MessageField;
use protocols::agent::{CgroupStats, CpuStats};
use serde::{Deserialize, Serialize};
use utils::*;

use super::{CgroupManager, DevicesCgroupInfo};

pub(self) mod utils;

fn sl() -> slog::Logger {
    slog_scope::logger().new(o!("subsystem" => "cgroups"))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manager {
    pub paths: HashMap<String, String>,
    pub mounts: HashMap<String, String>,
    pub cpath: String,
    #[serde(skip)]
    cgroup: cgroups::Cgroup,
    #[serde(skip)]
    pod_cgroup: Option<cgroups::Cgroup>,
    #[serde(skip)]
    devcg_allowed_all: bool,
}

impl Manager {
    pub fn new(
        cpath: &str,
        spec: &Spec,
        devcg_info: Option<Arc<RwLock<DevicesCgroupInfo>>>,
    ) -> Result<Self> {
        let (paths, mounts) = Self::get_paths_and_mounts(cpath).context("Get paths and mounts")?;

        // Do not expect poisoning lock
        let mut devices_group_info = devcg_info.as_ref().map(|i| i.write().unwrap());
        let pod_cgroup: Option<Cgroup>;

        if let Some(devices_group_info) = devices_group_info.as_mut() {
            // Cgroup path of parent of container
            let pod_cpath = PathBuf::from(cpath)
                .parent()
                .unwrap_or(Path::new("/"))
                .display()
                .to_string();

            if pod_cpath.as_str() == "/" {
                // Skip setting pod cgroup for cpath due to no parent path
                pod_cgroup = None
            } else {
                // Create a cgroup for the pod if not exists.
                // Note that creating pod cgroup MUST be done before the pause
                // container's cgroup created, since the upper node might have
                // some excessive permissions, and children inherit upper
                // node's rules. You'll feel painful to shrink upper nodes'
                // permissions if the new permissions are subset of old.
                pod_cgroup = Some(load_cgroup(cgroups::hierarchies::auto(), &pod_cpath));
                let pod_cg = pod_cgroup.as_ref().unwrap();

                let is_allowded_all = Self::has_allowed_all_devices_rule(spec);
                if devices_group_info.inited {
                    debug!(sl(), "Devices cgroup has been initialzied.");

                    // Set allowed all devices to pod cgroup
                    if !devices_group_info.allowed_all && is_allowded_all {
                        info!(
                            sl(),
                            "Pod devices cgroup is changed to allowed all devices mode, \
                             devices_group_info = {:?}",
                            devices_group_info
                        );
                        Self::setup_allowed_all_mode(pod_cg).with_context(|| {
                            format!("Setup allowed all devices mode for {}", pod_cpath)
                        })?;
                        devices_group_info.allowed_all = true;
                    }
                } else {
                    // This is the first container (aka pause container)
                    debug!(sl(), "Started to init devices cgroup");

                    pod_cg.create().context("Create pod cgroup")?;

                    if !is_allowded_all {
                        Self::setup_devcg_whitelist(pod_cg).with_context(|| {
                            format!("Setup device cgroup whitelist for {}", pod_cpath)
                        })?;
                    } else {
                        Self::setup_allowed_all_mode(pod_cg)
                            .with_context(|| format!("Setup allowed all mode for {}", pod_cpath))?;
                        devices_group_info.allowed_all = true;
                    }

                    devices_group_info.inited = true
                }
            }
        } else {
            pod_cgroup = None;
        }

        // Create a cgroup for the container.
        let cg = new_cgroup(cgroups::hierarchies::auto(), cpath)?;
        // The rules of container cgroup are copied from its parent, which
        // contains some permissions that the container doesn't need.
        // Therefore, resetting the container's devices cgroup is required.
        if let Some(devices_group_info) = devices_group_info.as_ref() {
            if !devices_group_info.allowed_all {
                Self::setup_devcg_whitelist(&cg)
                    .with_context(|| format!("Setup device cgroup whitelist for {}", cpath))?;
            }
        }

        Ok(Self {
            paths,
            mounts,
            // rels: paths,
            cpath: cpath.to_string(),
            cgroup: cg,
            pod_cgroup,
            devcg_allowed_all: devices_group_info
                .map(|info| info.allowed_all)
                .unwrap_or(false),
        })
    }

    /// Create a cgroupfs manager for systemd cgroup.
    /// The device cgroup is disabled in systemd cgroup, given that it is
    /// implemented by eBPF.
    pub fn new_systemd(cpath: &str) -> Result<Self> {
        let (paths, mounts) = Self::get_paths_and_mounts(cpath).context("Get paths and mounts")?;

        let cg = new_cgroup(cgroups::hierarchies::auto(), cpath)?;

        Ok(Self {
            paths,
            mounts,
            cpath: cpath.to_string(),
            pod_cgroup: None,
            cgroup: cg,
            devcg_allowed_all: false,
        })
    }

    pub fn subcgroup(&self) -> &str {
        // Check if we're in a Docker-in-Docker setup by verifying:
        // 1. We're using cgroups v2 (which restricts direct process control)
        // 2. An "init" subdirectory exists (used by DinD for process delegation)
        let is_dind = cgroups::hierarchies::is_cgroup2_unified_mode()
            && cgroups::hierarchies::auto()
                .root()
                .join(&self.cpath)
                .join("init")
                .exists();
        if is_dind { "/init/" } else { "/" }
    }

    fn get_paths_and_mounts(
        cpath: &str,
    ) -> Result<(HashMap<String, String>, HashMap<String, String>)> {
        let mut m = HashMap::new();

        let paths = get_paths()?;
        let mounts = get_mounts(&paths)?;

        for key in paths.keys() {
            let mnt = mounts.get(key);

            if mnt.is_none() {
                continue;
            }

            m.insert(key.to_string(), format!("{}/{}", mnt.unwrap(), cpath));
        }

        Ok((m, mounts))
    }

    fn setup_allowed_all_mode(cgroup: &cgroups::Cgroup) -> Result<()> {
        // Insert two rules: `b *:* rwm` and `c *:* rwm`.
        // The reason of not inserting `a *:* rwm` is that the Linux kernel
        // will deny writing `a` to `devices.allow` once a cgroup has
        // children. You can refer to
        // https://www.kernel.org/doc/Documentation/cgroup-v1/devices.txt.
        let res = cgroups::Resources {
            devices: cgroups::DeviceResources {
                devices: vec![
                    DeviceResource {
                        allow: true,
                        devtype: DeviceType::Block,
                        major: -1,
                        minor: -1,
                        access: vec![
                            DevicePermissions::Read,
                            DevicePermissions::Write,
                            DevicePermissions::MkNod,
                        ],
                    },
                    DeviceResource {
                        allow: true,
                        devtype: DeviceType::Char,
                        major: -1,
                        minor: -1,
                        access: vec![
                            DevicePermissions::Read,
                            DevicePermissions::Write,
                            DevicePermissions::MkNod,
                        ],
                    },
                ],
            },
            ..Default::default()
        };
        cgroup.apply(&res)?;

        Ok(())
    }

    /// Setup device cgroup whitelist:
    /// - Deny all devices in order to cleanup device cgroup.
    /// - Allow default devices and default allowed devices.
    fn setup_devcg_whitelist(cgroup: &cgroups::Cgroup) -> Result<()> {
        #[allow(unused_mut)]
        let mut dev_res_list = vec![DeviceResource {
            allow: false,
            devtype: DeviceType::All,
            major: -1,
            minor: -1,
            access: vec![
                DevicePermissions::Read,
                DevicePermissions::Write,
                DevicePermissions::MkNod,
            ],
        }];
        // Do not append default allowed devices for simplicity while
        // testing.
        #[cfg(not(test))]
        dev_res_list.append(&mut default_allowed_devices());

        let res = cgroups::Resources {
            devices: cgroups::DeviceResources {
                devices: dev_res_list,
            },
            ..Default::default()
        };
        cgroup.apply(&res)?;

        Ok(())
    }

    /// Check if OCI spec contains a rule of allowed all devices.
    fn has_allowed_all_devices_rule(spec: &Spec) -> bool {
        let linux = match spec.linux().as_ref() {
            Some(linux) => linux,
            None => return false,
        };
        let resources = match linux.resources().as_ref() {
            Some(resource) => resource,
            None => return false,
        };

        resources
            .devices()
            .as_ref()
            .and_then(|devices| {
                devices
                    .iter()
                    .find(|dev| super::rule_for_all_devices(dev))
                    .map(|dev| dev.allow())
            })
            .unwrap_or_default()
    }
}

impl CgroupManager for Manager {
    fn apply(&self, pid: pid_t) -> Result<()> {
        self.cgroup.add_task_by_tgid(CgroupPid::from(pid as u64))?;
        Ok(())
    }

    fn set(&self, r: &LinuxResources, update: bool) -> Result<()> {
        info!(
            sl(),
            "cgroup manager set resources for container. Resources input {:?}", r
        );

        let res = &mut cgroups::Resources::default();
        let pod_res = &mut cgroups::Resources::default();

        // set cpuset and cpu reources
        if let Some(cpu) = &r.cpu() {
            set_cpu_resources(&self.cgroup, cpu)?;
        }

        // set memory resources
        if let Some(memory) = &r.memory() {
            set_memory_resources(&self.cgroup, memory, update)?;
        }

        // set pids resources
        if let Some(pids_resources) = &r.pids() {
            set_pids_resources(&self.cgroup, pids_resources)?;
        }

        // set block_io resources
        if let Some(blkio) = &r.block_io() {
            set_block_io_resources(&self.cgroup, blkio, res);
        }

        // set hugepages resources
        if let Some(hugepage_limits) = r.hugepage_limits() {
            set_hugepages_resources(&self.cgroup, hugepage_limits, res);
        }

        // set network resources
        if let Some(network) = &r.network() {
            set_network_resources(&self.cgroup, network, res);
        }

        // set devices resources
        if !self.devcg_allowed_all {
            if let Some(devices) = r.devices() {
                set_devices_resources(&self.cgroup, devices, res, pod_res);
            }
        }
        debug!(
            sl(),
            "Resources after processed, pod_res = {:?}, res = {:?}", pod_res, res
        );

        // apply resources
        if let Some(pod_cg) = self.pod_cgroup.as_ref() {
            pod_cg.apply(pod_res)?;
        }
        self.cgroup.apply(res)?;

        Ok(())
    }

    fn get_stats(&self) -> Result<CgroupStats> {
        // CpuStats
        let cpu_usage = get_cpuacct_stats(&self.cgroup);

        let throttling_data = get_cpu_stats(&self.cgroup);

        let cpu_stats = MessageField::some(CpuStats {
            cpu_usage,
            throttling_data,
            ..Default::default()
        });

        // Memorystats
        let memory_stats = get_memory_stats(&self.cgroup);

        // PidsStats
        let pids_stats = get_pids_stats(&self.cgroup);

        // BlkioStats
        // note that virtiofs has no blkio stats
        let blkio_stats = get_blkio_stats(&self.cgroup);

        // HugetlbStats
        let hugetlb_stats = get_hugetlb_stats(&self.cgroup);

        Ok(CgroupStats {
            cpu_stats,
            memory_stats,
            pids_stats,
            blkio_stats,
            hugetlb_stats,
            ..Default::default()
        })
    }

    fn freeze(&self, state: FreezerState) -> Result<()> {
        let freezer_controller: &FreezerController = self.cgroup.controller_of().unwrap();
        match state {
            FreezerState::Thawed => {
                freezer_controller.thaw()?;
            }
            FreezerState::Frozen => {
                freezer_controller.freeze()?;
            }
            _ => {
                return Err(anyhow!("Invalid FreezerState"));
            }
        }

        Ok(())
    }

    fn destroy(&mut self) -> Result<()> {
        if let Err(err) = self.cgroup.delete() {
            warn!(
                sl(),
                "Failed to delete cgroup {}: {}",
                self.cgroup.path(),
                err
            );
        }
        Ok(())
    }

    fn get_pids(&self) -> Result<Vec<pid_t>> {
        let mem_controller: &MemController = self.cgroup.controller_of().unwrap();
        let pids = mem_controller.tasks();
        let result = pids.iter().map(|x| x.pid as i32).collect::<Vec<i32>>();

        Ok(result)
    }

    fn update_cpuset_path(&self, guest_cpuset: &str, container_cpuset: &str) -> Result<()> {
        if guest_cpuset.is_empty() {
            return Ok(());
        }
        info!(sl(), "update_cpuset_path to: {}", guest_cpuset);

        let h = cgroups::hierarchies::auto();
        let root_cg = h.root_control_group();

        let root_cpuset_controller: &CpuSetController = root_cg.controller_of().unwrap();
        let path = root_cpuset_controller.path();
        let root_path = Path::new(path);
        info!(sl(), "root cpuset path: {:?}", &path);

        let container_cpuset_controller: &CpuSetController = self.cgroup.controller_of().unwrap();
        let path = container_cpuset_controller.path();
        let container_path = Path::new(path);
        info!(sl(), "container cpuset path: {:?}", &path);

        let mut paths = vec![];
        for ancestor in container_path.ancestors() {
            if ancestor == root_path {
                break;
            }
            paths.push(ancestor);
        }
        info!(sl(), "parent paths to update cpuset: {:?}", &paths);

        let mut i = paths.len();
        loop {
            if i == 0 {
                break;
            }
            i -= 1;

            // remove cgroup root from path
            let r_path = &paths[i]
                .to_str()
                .unwrap()
                .trim_start_matches(root_path.to_str().unwrap());
            info!(sl(), "updating cpuset for parent path {:?}", &r_path);
            let cg = new_cgroup(cgroups::hierarchies::auto(), r_path)?;
            let cpuset_controller: &CpuSetController = cg.controller_of().unwrap();
            cpuset_controller.set_cpus(guest_cpuset)?;
        }

        if !container_cpuset.is_empty() {
            info!(
                sl(),
                "updating cpuset for container path: {:?} cpuset: {}",
                &container_path,
                container_cpuset
            );
            container_cpuset_controller.set_cpus(container_cpuset)?;
        }

        Ok(())
    }

    fn get_cgroup_path(&self, cg: &str) -> Result<String> {
        if cgroups::hierarchies::is_cgroup2_unified_mode() {
            let cg_path = format!("/sys/fs/cgroup/{}", self.cpath);
            return Ok(cg_path);
        }

        // for cgroup v1
        Ok(self.paths.get(cg).map(|s| s.to_string()).unwrap())
    }

    fn as_any(&self) -> Result<&dyn Any> {
        Ok(self)
    }

    fn name(&self) -> &str {
        "cgroupfs"
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        process::Command,
        sync::{Arc, RwLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use cgroups::devices::{DevicePermissions, DeviceType};
    use oci::{
        LinuxBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder, LinuxDeviceType,
        LinuxResourcesBuilder, SpecBuilder,
    };
    use oci_spec::runtime as oci;
    use test_utils::skip_if_not_root;

    use super::default_allowed_devices;
    use crate::{
        cgroups::{
            DevicesCgroupInfo,
            fs::{DEFAULT_ALLOWED_DEVICES, Manager, WILDCARD, line_to_vec, lines_to_map},
        },
        container::DEFAULT_DEVICES,
    };

    #[test]
    fn test_line_to_vec() {
        let test_cases = vec![
            ("1 2 3", vec![1, 2, 3]),
            ("a 1 b 2 3 c", vec![1, 2, 3]),
            ("a b c", vec![]),
        ];

        for test_case in test_cases {
            let result = line_to_vec(test_case.0);
            assert_eq!(
                result, test_case.1,
                "except: {:?} for input {}",
                test_case.1, test_case.0
            );
        }
    }

    #[test]
    fn test_lines_to_map() {
        let hm1: HashMap<String, u64> = [
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
            ("e".to_string(), 5),
        ]
        .iter()
        .cloned()
        .collect();
        let hm2: HashMap<String, u64> = [("a".to_string(), 1)].iter().cloned().collect();

        let test_cases = vec![
            ("a 1\nb 2\nc 3\nd X\ne 5\n", hm1),
            ("a 1", hm2),
            ("a c", HashMap::new()),
        ];

        for test_case in test_cases {
            let result = lines_to_map(test_case.0);
            assert_eq!(
                result, test_case.1,
                "except: {:?} for input {}",
                test_case.1, test_case.0
            );
        }
    }

    struct MockSandbox {
        devcg_info: Arc<RwLock<DevicesCgroupInfo>>,
    }

    impl MockSandbox {
        fn new() -> Self {
            Self {
                devcg_info: Arc::new(RwLock::new(DevicesCgroupInfo::default())),
            }
        }
    }

    #[test]
    fn test_new_fs_manager() {
        skip_if_not_root!();

        let output = Command::new("stat")
            .arg("-f")
            .arg("-c")
            .arg("%T")
            .arg("/sys/fs/cgroup/")
            .output()
            .unwrap();
        let output_str = String::from_utf8(output.stdout).unwrap();
        let cgroup_version = output_str.strip_suffix("\n").unwrap();
        if cgroup_version.eq("cgroup2fs") {
            println!("INFO: Skipping the test as cgroups v2 is used by default");
            return;
        }

        struct TestCase {
            cpath: Vec<String>,
            devices: Vec<Vec<LinuxDeviceCgroup>>,
            allowed_all: Vec<bool>,
            pod_devices_list: Vec<String>,
            container_devices_list: Vec<String>,
        }

        let allow_all = LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(LinuxDeviceType::A)
            .major(0)
            .minor(0)
            .access("rwm")
            .build()
            .unwrap();
        let deny_all = LinuxDeviceCgroupBuilder::default()
            .allow(false)
            .typ(LinuxDeviceType::A)
            .major(0)
            .minor(0)
            .access("rwm")
            .build()
            .unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let one_time_pod_name = format!("kata-agent-fs-manager-test-{}", now);
        let one_time_cpath =
            |child: &str| -> String { format!("/{}/{}", one_time_pod_name, child) };

        let test_cases = vec![
            TestCase {
                cpath: vec![one_time_cpath("child1")],
                devices: vec![vec![allow_all.clone()]],
                allowed_all: vec![true],
                pod_devices_list: vec![String::from("a *:* rwm\n")],
                container_devices_list: vec![String::from("a *:* rwm\n")],
            },
            TestCase {
                cpath: vec![one_time_cpath("child1")],
                devices: vec![vec![deny_all.clone()]],
                allowed_all: vec![false],
                pod_devices_list: vec![String::new()],
                container_devices_list: vec![String::new()],
            },
            TestCase {
                cpath: vec![one_time_cpath("child1"), one_time_cpath("child2")],
                devices: vec![vec![deny_all.clone()], vec![allow_all.clone()]],
                allowed_all: vec![false, true],
                pod_devices_list: vec![String::new(), String::from("b *:* rwm\nc *:* rwm\n")],
                container_devices_list: vec![String::new(), String::from("b *:* rwm\nc *:* rwm\n")],
            },
            TestCase {
                cpath: vec![one_time_cpath("child1"), one_time_cpath("child2")],
                devices: vec![vec![allow_all], vec![deny_all]],
                allowed_all: vec![true, true],
                pod_devices_list: vec![String::from("a *:* rwm\n"), String::from("a *:* rwm\n")],
                container_devices_list: vec![
                    String::from("a *:* rwm\n"),
                    String::from("a *:* rwm\n"),
                ],
            },
        ];

        for (round, tc) in test_cases.iter().enumerate() {
            let sandbox = MockSandbox::new();
            let devcg_info = sandbox.devcg_info.read().unwrap();
            assert!(!devcg_info.inited);
            assert!(!devcg_info.allowed_all);
            drop(devcg_info);
            let mut managers = Vec::with_capacity(tc.devices.len());

            for cid in 0..tc.devices.len() {
                let spec = SpecBuilder::default()
                    .linux(
                        LinuxBuilder::default()
                            .resources(
                                LinuxResourcesBuilder::default()
                                    .devices(tc.devices[cid].clone())
                                    .build()
                                    .unwrap(),
                            )
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap();
                managers.push(
                    Manager::new(&tc.cpath[cid], &spec, Some(sandbox.devcg_info.clone())).unwrap(),
                );

                let devcg_info = sandbox.devcg_info.read().unwrap();
                assert!(devcg_info.inited);
                assert_eq!(
                    devcg_info.allowed_all, tc.allowed_all[cid],
                    "Test case {}: cid {} allowed all assertion failure",
                    round, cid
                );
                drop(devcg_info);

                let pod_devices_list = Command::new("cat")
                    .arg(&format!(
                        "/sys/fs/cgroup/devices/{}/devices.list",
                        one_time_pod_name
                    ))
                    .output()
                    .unwrap();
                let container_devices_list = Command::new("cat")
                    .arg(&format!(
                        "/sys/fs/cgroup/devices{}/devices.list",
                        tc.cpath[cid]
                    ))
                    .output()
                    .unwrap();

                let pod_devices_list = String::from_utf8(pod_devices_list.stdout).unwrap();
                let container_devices_list =
                    String::from_utf8(container_devices_list.stdout).unwrap();

                assert_eq!(
                    &pod_devices_list, &tc.pod_devices_list[cid],
                    "Test case {}: cid {} allowed all assertion failure",
                    round, cid
                );
                assert_eq!(
                    &container_devices_list, &tc.container_devices_list[cid],
                    "Test case {}: cid {} allowed all assertion failure",
                    round, cid
                )
            }

            // Clean up cgroups
            managers
                .iter()
                .for_each(|manager| manager.cgroup.delete().unwrap());
            // The pod_cgroup must not be None
            managers[0].pod_cgroup.as_ref().unwrap().delete().unwrap();
        }
    }

    #[test]
    fn test_default_allowed_devices() {
        let allowed_devices = default_allowed_devices();
        assert_eq!(
            allowed_devices.len(),
            DEFAULT_DEVICES.len() + DEFAULT_ALLOWED_DEVICES.len()
        );

        let allowed_permissions = vec![
            DevicePermissions::Read,
            DevicePermissions::Write,
            DevicePermissions::MkNod,
        ];

        let default_devices_0 = &allowed_devices[0];
        assert!(default_devices_0.allow);
        assert_eq!(default_devices_0.devtype, DeviceType::Char);
        assert_eq!(default_devices_0.major, 1);
        assert_eq!(default_devices_0.minor, 3);
        assert!(
            default_devices_0
                .access
                .iter()
                .all(|&p| allowed_permissions.iter().any(|&ap| ap == p))
        );

        let default_allowed_devices_0 = &allowed_devices[DEFAULT_DEVICES.len()];
        assert!(default_allowed_devices_0.allow);
        assert_eq!(default_allowed_devices_0.devtype, DeviceType::Char);
        assert_eq!(default_allowed_devices_0.major, WILDCARD);
        assert_eq!(default_allowed_devices_0.minor, WILDCARD);
        assert_eq!(
            default_allowed_devices_0.access,
            vec![DevicePermissions::MkNod]
        );
    }
}
