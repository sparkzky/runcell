use std::{collections::HashMap, fs};

use anyhow::{Context, Result, anyhow};
use cgroups::{
    BlkIoDeviceResource, BlkIoDeviceThrottleResource, Cgroup, DeviceResource, HugePageResource,
    MaxValue, NetworkPriority,
    blkio::{BlkIoController, BlkIoData, IoService},
    cpu::CpuController,
    cpuacct::CpuAcctController,
    cpuset::CpuSetController,
    devices::{DevicePermissions, DeviceType},
    hugetlb::HugeTlbController,
    memory::MemController,
    pid::PidController,
};
use libc::{self};
use oci::{
    LinuxBlockIo, LinuxCpu, LinuxDevice, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxHugepageLimit, LinuxMemory, LinuxNetwork, LinuxPids,
};
use oci_spec::runtime as oci;
use protobuf::MessageField;
use protocols::agent::{
    BlkioStats, BlkioStatsEntry, CpuUsage, HugetlbStats, MemoryData, MemoryStats, PidsStats,
    ThrottlingData,
};

use super::sl;
use crate::{cgroups::rule_for_all_devices, container::DEFAULT_DEVICES};

const GUEST_CPUS_PATH: &str = "/sys/devices/system/cpu/online";

/// Set resource macro for cgroup controllers
macro_rules! set_resource {
    ($cont:ident, $func:ident, $res:ident, $field:ident) => {
        let resource_value = $res.$field().unwrap_or(0);
        if resource_value != 0 {
            $cont.$func(resource_value)?;
        }
    };
}

macro_rules! get_controller_or_return_singular_none {
    ($cg:ident) => {
        match $cg.controller_of() {
            Some(c) => c,
            None => return MessageField::none(),
        }
    };
}

pub fn set_network_resources(
    _cg: &cgroups::Cgroup,
    network: &LinuxNetwork,
    res: &mut cgroups::Resources,
) {
    info!(sl(), "cgroup manager set network");

    // set classid
    // description can be found at https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/net_cls.html
    let class_id = network.class_id().unwrap_or(0) as u64;
    if class_id != 0 {
        res.network.class_id = Some(class_id);
    }

    // set network priorities
    // description can be found at https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/net_prio.html
    let mut priorities = vec![];
    let interface_priority = network.priorities().clone().unwrap_or_default();
    for p in interface_priority.iter() {
        priorities.push(NetworkPriority {
            name: p.name().clone(),
            priority: p.priority() as u64,
        });
    }

    res.network.priorities = priorities;
}

pub fn set_devices_resources(
    _cg: &cgroups::Cgroup,
    device_resources: &[LinuxDeviceCgroup],
    res: &mut cgroups::Resources,
    pod_res: &mut cgroups::Resources,
) {
    info!(sl(), "cgroup manager set devices");
    let mut devices = vec![];

    for d in device_resources.iter() {
        if rule_for_all_devices(d) {
            continue;
        }
        if let Some(dev) = linux_device_cgroup_to_device_resource(d) {
            devices.push(dev);
        }
    }

    pod_res.devices.devices = devices.clone();
    res.devices.devices = devices;
}

pub fn set_hugepages_resources(
    cg: &cgroups::Cgroup,
    hugepage_limits: &[LinuxHugepageLimit],
    res: &mut cgroups::Resources,
) {
    info!(sl(), "cgroup manager set hugepage");
    let mut limits = vec![];
    let hugetlb_controller = cg.controller_of::<HugeTlbController>();

    for l in hugepage_limits.iter() {
        if hugetlb_controller.is_some() && hugetlb_controller.unwrap().size_supported(l.page_size())
        {
            let hr = HugePageResource {
                size: l.page_size().clone(),
                limit: l.limit() as u64,
            };
            limits.push(hr);
        } else {
            warn!(
                sl(),
                "{} page size support cannot be verified, dropping requested limit",
                l.page_size()
            );
        }
    }
    res.hugepages.limits = limits;
}

pub fn set_block_io_resources(
    _cg: &cgroups::Cgroup,
    blkio: &LinuxBlockIo,
    res: &mut cgroups::Resources,
) {
    info!(sl(), "cgroup manager set block io");

    res.blkio.weight = blkio.weight();
    res.blkio.leaf_weight = blkio.leaf_weight();

    let mut blk_device_resources = vec![];
    let default_weight_device = vec![];
    let weight_device = blkio
        .weight_device()
        .as_ref()
        .unwrap_or(&default_weight_device);
    for d in weight_device.iter() {
        let dr = BlkIoDeviceResource {
            major: d.major() as u64,
            minor: d.minor() as u64,
            weight: blkio.weight(),
            leaf_weight: blkio.leaf_weight(),
        };
        blk_device_resources.push(dr);
    }
    res.blkio.weight_device = blk_device_resources;

    res.blkio.throttle_read_bps_device = build_blk_io_device_throttle_resource(
        blkio.throttle_read_bps_device().as_ref().unwrap_or(&vec![]),
    );
    res.blkio.throttle_write_bps_device = build_blk_io_device_throttle_resource(
        blkio
            .throttle_write_bps_device()
            .as_ref()
            .unwrap_or(&vec![]),
    );
    res.blkio.throttle_read_iops_device = build_blk_io_device_throttle_resource(
        blkio
            .throttle_read_iops_device()
            .as_ref()
            .unwrap_or(&vec![]),
    );
    res.blkio.throttle_write_iops_device = build_blk_io_device_throttle_resource(
        blkio
            .throttle_write_iops_device()
            .as_ref()
            .unwrap_or(&vec![]),
    );
}

pub fn set_cpu_resources(cg: &cgroups::Cgroup, cpu: &LinuxCpu) -> Result<()> {
    info!(sl(), "cgroup manager set cpu");

    let cpuset_controller: &CpuSetController = cg.controller_of().unwrap();

    if let Some(cpus) = cpu.cpus() {
        if let Err(e) = cpuset_controller.set_cpus(cpus) {
            warn!(sl(), "write cpuset failed: {:?}", e);
        }
    }

    if let Some(mems) = cpu.mems() {
        cpuset_controller.set_mems(mems)?;
    }

    let cpu_controller: &CpuController = cg.controller_of().unwrap();

    if let Some(shares) = cpu.shares() {
        let shares = if cg.v2() {
            convert_shares_to_v2_value(shares)
        } else {
            shares
        };
        if shares != 0 {
            cpu_controller.set_shares(shares)?;
        }
    }

    set_resource!(cpu_controller, set_cfs_quota, cpu, quota);
    set_resource!(cpu_controller, set_cfs_period, cpu, period);

    set_resource!(cpu_controller, set_rt_runtime, cpu, realtime_runtime);
    set_resource!(cpu_controller, set_rt_period_us, cpu, realtime_period);

    Ok(())
}

pub fn set_memory_resources(
    cg: &cgroups::Cgroup,
    memory: &LinuxMemory,
    update: bool,
) -> Result<()> {
    info!(sl(), "cgroup manager set memory");
    let mem_controller: &MemController = cg.controller_of().unwrap();

    if !update {
        // initialize kmem limits for accounting
        mem_controller.set_kmem_limit(1)?;
        mem_controller.set_kmem_limit(-1)?;
    }

    // If the memory update is set to -1 we should also
    // set swap to -1, it means unlimited memory.
    let mut swap = memory.swap().unwrap_or(0);
    if memory.limit() == Some(-1) {
        swap = -1;
    }

    if memory.limit().is_some() && swap != 0 {
        let memstat = get_memory_stats(cg)
            .into_option()
            .ok_or_else(|| anyhow!("failed to get the cgroup memory stats"))?;
        let memusage = memstat.usage();

        // When update memory limit, the kernel would check the current memory limit
        // set against the new swap setting, if the current memory limit is large than
        // the new swap, then set limit first, otherwise the kernel would complain and
        // refused to set; on the other hand, if the current memory limit is smaller
        // than the new swap, then we should set the swap first and then set the
        // memor limit.
        if swap == -1 || memusage.limit() < swap as u64 {
            mem_controller.set_memswap_limit(swap)?;
            set_resource!(mem_controller, set_limit, memory, limit);
        } else {
            set_resource!(mem_controller, set_limit, memory, limit);
            mem_controller.set_memswap_limit(swap)?;
        }
    } else {
        set_resource!(mem_controller, set_limit, memory, limit);
        swap = if cg.v2() {
            convert_memory_swap_to_v2_value(swap, memory.limit().unwrap_or(0))?
        } else {
            swap
        };
        if swap != 0 {
            mem_controller.set_memswap_limit(swap)?;
        }
    }

    set_resource!(mem_controller, set_soft_limit, memory, reservation);
    set_resource!(mem_controller, set_kmem_limit, memory, kernel);
    set_resource!(mem_controller, set_tcp_limit, memory, kernel_tcp);

    if let Some(swappiness) = memory.swappiness() {
        if (0..=100).contains(&swappiness) {
            mem_controller.set_swappiness(swappiness)?;
        } else {
            return Err(anyhow!(
                "invalid value:{}. valid memory swappiness range is 0-100",
                swappiness
            ));
        }
    }

    if memory.disable_oom_killer().unwrap_or(false) {
        mem_controller.disable_oom_killer()?;
    }

    Ok(())
}

pub fn set_pids_resources(cg: &cgroups::Cgroup, pids: &LinuxPids) -> Result<()> {
    info!(sl(), "cgroup manager set pids");
    let pid_controller: &PidController = cg.controller_of().unwrap();
    let v = if pids.limit() > 0 {
        MaxValue::Value(pids.limit())
    } else {
        MaxValue::Max
    };
    pid_controller
        .set_pid_max(v)
        .context("failed to set pids resources")
}

pub fn build_blk_io_device_throttle_resource(
    input: &[oci::LinuxThrottleDevice],
) -> Vec<BlkIoDeviceThrottleResource> {
    let mut blk_io_device_throttle_resources = vec![];
    for d in input.iter() {
        let tr = BlkIoDeviceThrottleResource {
            major: d.major() as u64,
            minor: d.minor() as u64,
            rate: d.rate(),
        };
        blk_io_device_throttle_resources.push(tr);
    }

    blk_io_device_throttle_resources
}

pub fn linux_device_cgroup_to_device_resource(d: &LinuxDeviceCgroup) -> Option<DeviceResource> {
    let dev_type = DeviceType::from_char(d.typ().unwrap_or_default().as_str().chars().next())?;

    let mut permissions: Vec<DevicePermissions> = vec![];
    for p in d
        .access()
        .as_ref()
        .unwrap_or(&"".to_owned())
        .chars()
        .collect::<Vec<char>>()
    {
        match p {
            'r' => permissions.push(DevicePermissions::Read),
            'w' => permissions.push(DevicePermissions::Write),
            'm' => permissions.push(DevicePermissions::MkNod),
            _ => {}
        }
    }

    Some(DeviceResource {
        allow: d.allow(),
        devtype: dev_type,
        major: d.major().unwrap_or(0),
        minor: d.minor().unwrap_or(0),
        access: permissions,
    })
}

pub fn line_to_vec(line: &str) -> Vec<u64> {
    line.split_whitespace()
        .filter_map(|x| x.parse::<u64>().ok())
        .collect::<Vec<u64>>()
}

pub fn lines_to_map(content: &str) -> HashMap<String, u64> {
    content
        .lines()
        .map(|x| x.split_whitespace().collect::<Vec<&str>>())
        .filter(|x| x.len() == 2 && x[1].parse::<u64>().is_ok())
        .fold(HashMap::new(), |mut hm, x| {
            hm.insert(x[0].to_string(), x[1].parse::<u64>().unwrap());
            hm
        })
}

pub const NANO_PER_SECOND: u64 = 1000000000;
pub const WILDCARD: i64 = -1;

lazy_static! {
    pub static ref CLOCK_TICKS: f64 = {
        let n = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };

        n as f64
    };

    pub static ref DEFAULT_ALLOWED_DEVICES: Vec<LinuxDeviceCgroup> = {
        vec![
            // all mknod to all char devices
            LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .typ(oci::LinuxDeviceType::C)
                .major(WILDCARD)
                .minor(WILDCARD)
                .access("m")
                .build()
                .unwrap(),

            // all mknod to all block devices
            LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .typ(oci::LinuxDeviceType::B)
                .major(WILDCARD)
                .minor(WILDCARD)
                .access("m")
                .build()
                .unwrap(),

            // all read/write/mknod to char device /dev/console
            LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .typ(oci::LinuxDeviceType::C)
                .major(5)
                .minor(1)
                .access("rwm")
                .build()
                .unwrap(),

            // all read/write/mknod to char device /dev/pts/<N>
            LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .typ(oci::LinuxDeviceType::C)
                .major(136)
                .minor(WILDCARD)
                .access("rwm")
                .build()
                .unwrap(),

            // all read/write/mknod to char device /dev/ptmx
            LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .typ(oci::LinuxDeviceType::C)
                .major(5)
                .minor(2)
                .access("rwm")
                .build()
                .unwrap(),

            // all read/write/mknod to char device /dev/net/tun
            LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .typ(oci::LinuxDeviceType::C)
                .major(10)
                .minor(200)
                .access("rwm")
                .build()
                .unwrap(),
        ]
    };
}

pub fn get_cpu_stats(cg: &cgroups::Cgroup) -> MessageField<ThrottlingData> {
    let cpu_controller: &CpuController = get_controller_or_return_singular_none!(cg);
    let stat = cpu_controller.cpu().stat;
    let h = lines_to_map(&stat);

    MessageField::some(ThrottlingData {
        periods: *h.get("nr_periods").unwrap_or(&0),
        throttled_periods: *h.get("nr_throttled").unwrap_or(&0),
        throttled_time: *h.get("throttled_time").unwrap_or(&0),
        ..Default::default()
    })
}

pub fn get_cpuacct_stats(cg: &cgroups::Cgroup) -> MessageField<CpuUsage> {
    if let Some(cpuacct_controller) = cg.controller_of::<CpuAcctController>() {
        let cpuacct = cpuacct_controller.cpuacct();

        let h = lines_to_map(&cpuacct.stat);
        let usage_in_usermode =
            (((*h.get("user").unwrap_or(&0) * NANO_PER_SECOND) as f64) / *CLOCK_TICKS) as u64;
        let usage_in_kernelmode =
            (((*h.get("system").unwrap_or(&0) * NANO_PER_SECOND) as f64) / *CLOCK_TICKS) as u64;

        let total_usage = cpuacct.usage;

        let percpu_usage = line_to_vec(&cpuacct.usage_percpu);

        return MessageField::some(CpuUsage {
            total_usage,
            percpu_usage,
            usage_in_kernelmode,
            usage_in_usermode,
            ..Default::default()
        });
    }

    // try to get from cpu controller
    let cpu_controller: &CpuController = get_controller_or_return_singular_none!(cg);
    let stat = cpu_controller.cpu().stat;
    let h = lines_to_map(&stat);
    // All fields in CpuUsage are expressed in nanoseconds (ns).
    //
    // For cgroup v1 (cpuacct controller):
    // kata-agent reads the cpuacct.stat file, which reports the number of ticks
    // consumed by the processes in the cgroup. It then converts these ticks to
    // nanoseconds. Ref: https://www.kernel.org/doc/Documentation/cgroup-v1/cpuacct.txt
    //
    // For cgroup v2 (cpu controller):
    // kata-agent reads the cpu.stat file, which reports the time consumed by the
    // processes in the cgroup in microseconds (us). It then converts microseconds
    // to nanoseconds. Ref: https://www.kernel.org/doc/Documentation/cgroup-v2.txt, section 5-1-1. CPU Interface Files
    let usage_in_usermode = *h.get("user_usec").unwrap_or(&0) * 1000;
    let usage_in_kernelmode = *h.get("system_usec").unwrap_or(&0) * 1000;
    let total_usage = *h.get("usage_usec").unwrap_or(&0) * 1000;
    let percpu_usage = vec![];

    MessageField::some(CpuUsage {
        total_usage,
        percpu_usage,
        usage_in_kernelmode,
        usage_in_usermode,
        ..Default::default()
    })
}

pub fn get_memory_stats(cg: &cgroups::Cgroup) -> MessageField<MemoryStats> {
    let memory_controller: &MemController = get_controller_or_return_singular_none!(cg);

    // cache from memory stat
    let memory = memory_controller.memory_stat();
    let cache = memory.stat.cache;

    // use_hierarchy
    let value = memory.use_hierarchy;
    let use_hierarchy = value == 1;

    // get memory data
    let usage = MessageField::some(MemoryData {
        usage: memory.usage_in_bytes,
        max_usage: memory.max_usage_in_bytes,
        failcnt: memory.fail_cnt,
        limit: memory.limit_in_bytes as u64,
        ..Default::default()
    });

    // get swap usage
    let memswap = memory_controller.memswap();

    let swap_usage = MessageField::some(MemoryData {
        usage: memswap.usage_in_bytes,
        max_usage: memswap.max_usage_in_bytes,
        failcnt: memswap.fail_cnt,
        limit: memswap.limit_in_bytes as u64,
        ..Default::default()
    });

    // get kernel usage
    let kmem_stat = memory_controller.kmem_stat();

    let kernel_usage = MessageField::some(MemoryData {
        usage: kmem_stat.usage_in_bytes,
        max_usage: kmem_stat.max_usage_in_bytes,
        failcnt: kmem_stat.fail_cnt,
        limit: kmem_stat.limit_in_bytes as u64,
        ..Default::default()
    });

    MessageField::some(MemoryStats {
        cache,
        usage,
        swap_usage,
        kernel_usage,
        use_hierarchy,
        stats: memory.stat.raw,
        ..Default::default()
    })
}

pub fn get_pids_stats(cg: &cgroups::Cgroup) -> MessageField<PidsStats> {
    let pid_controller: &PidController = get_controller_or_return_singular_none!(cg);

    let current = pid_controller.get_pid_current().unwrap_or(0);
    let max = pid_controller.get_pid_max();

    let limit = match max {
        Err(_) => 0,
        Ok(max) => match max {
            MaxValue::Value(v) => v,
            MaxValue::Max => 0,
        },
    } as u64;

    MessageField::some(PidsStats {
        current,
        limit,
        ..Default::default()
    })
}

// examples(from runc, cgroup v1):
// https://github.com/opencontainers/runc/blob/a5847db387ae28c0ca4ebe4beee1a76900c86414/libcontainer/cgroups/fs/blkio.go
//
// blkio.sectors
// 8:0 6792
//
// blkio.io_service_bytes
// 8:0 Read 1282048
// 8:0 Write 2195456
// 8:0 Sync 2195456
// 8:0 Async 1282048
// 8:0 Total 3477504
// Total 3477504
//
// blkio.io_serviced
// 8:0 Read 124
// 8:0 Write 104
// 8:0 Sync 104
// 8:0 Async 124
// 8:0 Total 228
// Total 228
//
// blkio.io_queued
// 8:0 Read 0
// 8:0 Write 0
// 8:0 Sync 0
// 8:0 Async 0
// 8:0 Total 0
// Total 0

pub fn get_blkio_stat_blkiodata(blkiodata: &[BlkIoData]) -> Vec<BlkioStatsEntry> {
    let mut m = Vec::new();
    if blkiodata.is_empty() {
        return m;
    }

    // blkio.time_recursive and blkio.sectors_recursive have no op field.
    let op = "".to_string();
    for d in blkiodata {
        m.push(BlkioStatsEntry {
            major: d.major as u64,
            minor: d.minor as u64,
            op: op.clone(),
            value: d.data,
            ..Default::default()
        });
    }

    m
}

pub fn get_blkio_stat_ioservice(services: &[IoService]) -> Vec<BlkioStatsEntry> {
    let mut m = Vec::new();

    if services.is_empty() {
        return m;
    }

    for s in services {
        m.push(build_blkio_stats_entry(s.major, s.minor, "read", s.read));
        m.push(build_blkio_stats_entry(s.major, s.minor, "write", s.write));
        m.push(build_blkio_stats_entry(s.major, s.minor, "sync", s.sync));
        m.push(build_blkio_stats_entry(
            s.major, s.minor, "async", s.r#async,
        ));
        m.push(build_blkio_stats_entry(s.major, s.minor, "total", s.total));
    }
    m
}

pub fn build_blkio_stats_entry(major: i16, minor: i16, op: &str, value: u64) -> BlkioStatsEntry {
    BlkioStatsEntry {
        major: major as u64,
        minor: minor as u64,
        op: op.to_string(),
        value,
        ..Default::default()
    }
}

pub fn get_blkio_stats_v2(cg: &cgroups::Cgroup) -> MessageField<BlkioStats> {
    let blkio_controller: &BlkIoController = get_controller_or_return_singular_none!(cg);
    let blkio = blkio_controller.blkio();

    let mut resp = BlkioStats::new();
    let mut blkio_stats = Vec::new();

    let stat = blkio.io_stat;
    for s in stat {
        blkio_stats.push(build_blkio_stats_entry(s.major, s.minor, "read", s.rbytes));
        blkio_stats.push(build_blkio_stats_entry(s.major, s.minor, "write", s.wbytes));
        blkio_stats.push(build_blkio_stats_entry(s.major, s.minor, "rios", s.rios));
        blkio_stats.push(build_blkio_stats_entry(s.major, s.minor, "wios", s.wios));
        blkio_stats.push(build_blkio_stats_entry(
            s.major, s.minor, "dbytes", s.dbytes,
        ));
        blkio_stats.push(build_blkio_stats_entry(s.major, s.minor, "dios", s.dios));
    }

    resp.io_service_bytes_recursive = blkio_stats;

    MessageField::some(resp)
}

pub fn get_blkio_stats(cg: &cgroups::Cgroup) -> MessageField<BlkioStats> {
    if cg.v2() {
        return get_blkio_stats_v2(cg);
    }

    let blkio_controller: &BlkIoController = get_controller_or_return_singular_none!(cg);
    let blkio = blkio_controller.blkio();

    let mut m = BlkioStats::new();
    let io_serviced_recursive = blkio.io_serviced_recursive;

    if io_serviced_recursive.is_empty() {
        // fall back to generic stats
        // blkio.throttle.io_service_bytes,
        // maybe io_service_bytes_recursive?
        // stick to runc for now
        m.io_service_bytes_recursive = get_blkio_stat_ioservice(&blkio.throttle.io_service_bytes);
        m.io_serviced_recursive = get_blkio_stat_ioservice(&blkio.throttle.io_serviced);
    } else {
        // Try to read CFQ stats available on all CFQ enabled kernels first
        // IoService type data
        m.io_service_bytes_recursive = get_blkio_stat_ioservice(&blkio.io_service_bytes_recursive);
        m.io_serviced_recursive = get_blkio_stat_ioservice(&io_serviced_recursive);
        m.io_queued_recursive = get_blkio_stat_ioservice(&blkio.io_queued_recursive);
        m.io_service_time_recursive = get_blkio_stat_ioservice(&blkio.io_service_time_recursive);
        m.io_wait_time_recursive = get_blkio_stat_ioservice(&blkio.io_wait_time_recursive);
        m.io_merged_recursive = get_blkio_stat_ioservice(&blkio.io_merged_recursive);

        // BlkIoData type data
        m.io_time_recursive = get_blkio_stat_blkiodata(&blkio.time_recursive);
        m.sectors_recursive = get_blkio_stat_blkiodata(&blkio.sectors_recursive);
    }

    MessageField::some(m)
}

pub fn get_hugetlb_stats(cg: &cgroups::Cgroup) -> HashMap<String, HugetlbStats> {
    let mut h = HashMap::new();

    let hugetlb_controller: Option<&HugeTlbController> = cg.controller_of();
    if hugetlb_controller.is_none() {
        return h;
    }
    let hugetlb_controller = hugetlb_controller.unwrap();

    let sizes = hugetlb_controller.get_sizes();
    for size in sizes {
        let usage = hugetlb_controller.usage_in_bytes(&size).unwrap_or(0);
        let max_usage = hugetlb_controller.max_usage_in_bytes(&size).unwrap_or(0);
        let failcnt = hugetlb_controller.failcnt(&size).unwrap_or(0);

        h.insert(
            size.to_string(),
            HugetlbStats {
                usage,
                max_usage,
                failcnt,
                ..Default::default()
            },
        );
    }

    h
}

pub const PATHS: &str = "/proc/self/cgroup";
pub const MOUNTS: &str = "/proc/self/mountinfo";

pub fn get_paths() -> Result<HashMap<String, String>> {
    let mut m = HashMap::new();
    for l in fs::read_to_string(PATHS)?.lines() {
        let fl: Vec<&str> = l.split(':').collect();
        if fl.len() != 3 {
            info!(sl(), "Corrupted cgroup data!");
            continue;
        }

        let keys: Vec<&str> = fl[1].split(',').collect();
        for key in &keys {
            m.insert(key.to_string(), fl[2].to_string());
        }
    }
    Ok(m)
}

pub fn get_mounts(paths: &HashMap<String, String>) -> Result<HashMap<String, String>> {
    let mut m = HashMap::new();

    for l in fs::read_to_string(MOUNTS)?.lines() {
        let p: Vec<&str> = l.splitn(2, " - ").collect();
        let pre: Vec<&str> = p[0].split(' ').collect();
        let post: Vec<&str> = p[1].split(' ').collect();

        if post.len() != 3 {
            warn!(sl(), "can't parse {} line {:?}", MOUNTS, l);
            continue;
        }

        if post[0] != "cgroup" && post[0] != "cgroup2" {
            continue;
        }

        let names: Vec<&str> = post[2].split(',').collect();

        for name in &names {
            if paths.contains_key(*name) {
                m.insert(name.to_string(), pre[4].to_string());
            }
        }
    }

    Ok(m)
}

#[inline]
pub fn new_cgroup(h: Box<dyn cgroups::Hierarchy>, path: &str) -> Result<Cgroup> {
    let valid_path = path.trim_start_matches('/').to_string();
    cgroups::Cgroup::new(h, valid_path.as_str()).map_err(anyhow::Error::from)
}

#[inline]
pub fn load_cgroup(h: Box<dyn cgroups::Hierarchy>, path: &str) -> Cgroup {
    let valid_path = path.trim_start_matches('/').to_string();
    cgroups::Cgroup::load(h, valid_path.as_str())
}

/// Generate a list for allowed devices including `DEFAULT_DEVICES` and
/// `DEFAULT_ALLOWED_DEVICES`.
pub fn default_allowed_devices() -> Vec<DeviceResource> {
    let mut dev_res_list = Vec::new();
    DEFAULT_DEVICES.iter().for_each(|dev| {
        if let Some(dev_res) = linux_device_to_device_resource(dev) {
            dev_res_list.push(dev_res)
        }
    });
    DEFAULT_ALLOWED_DEVICES.iter().for_each(|dev| {
        if let Some(dev_res) = linux_device_cgroup_to_device_resource(dev) {
            dev_res_list.push(dev_res)
        }
    });
    dev_res_list
}

/// Convert LinuxDevice to DeviceResource.
pub fn linux_device_to_device_resource(d: &LinuxDevice) -> Option<DeviceResource> {
    let dev_type = DeviceType::from_char(d.typ().as_str().chars().next())?;

    let permissions = vec![
        DevicePermissions::Read,
        DevicePermissions::Write,
        DevicePermissions::MkNod,
    ];

    Some(DeviceResource {
        allow: true,
        devtype: dev_type,
        major: d.major(),
        minor: d.minor(),
        access: permissions,
    })
}

// get the guest's online cpus.
pub fn get_guest_cpuset() -> Result<String> {
    let c = fs::read_to_string(GUEST_CPUS_PATH)?;
    Ok(c.trim().to_string())
}

// Since the OCI spec is designed for cgroup v1, in some cases
// there is need to convert from the cgroup v1 configuration to cgroup v2
// the formula for cpuShares is y = (1 + ((x - 2) * 9999) / 262142)
// convert from [2-262144] to [1-10000]
// 262144 comes from Linux kernel definition "#define MAX_SHARES (1UL << 18)"
// from https://github.com/opencontainers/runc/blob/a5847db387ae28c0ca4ebe4beee1a76900c86414/libcontainer/cgroups/utils.go#L394
pub fn convert_shares_to_v2_value(shares: u64) -> u64 {
    if shares == 0 {
        return 0;
    }
    1 + ((shares - 2) * 9999) / 262142
}

// ConvertMemorySwapToCgroupV2Value converts MemorySwap value from OCI spec
// for use by cgroup v2 drivers. A conversion is needed since
// Resources.MemorySwap is defined as memory+swap combined, while in cgroup v2
// swap is a separate value.
pub fn convert_memory_swap_to_v2_value(memory_swap: i64, memory: i64) -> Result<i64> {
    // for compatibility with cgroup1 controller, set swap to unlimited in
    // case the memory is set to unlimited, and swap is not explicitly set,
    // treating the request as "set both memory and swap to unlimited".
    if memory == -1 && memory_swap == 0 {
        return Ok(-1);
    }
    if memory_swap == -1 || memory_swap == 0 {
        // -1 is "max", 0 is "unset", so treat as is
        return Ok(memory_swap);
    }
    // sanity checks
    if memory == 0 || memory == -1 {
        return Err(anyhow!("unable to set swap limit without memory limit"));
    }
    if memory < 0 {
        return Err(anyhow!("invalid memory value: {}", memory));
    }
    if memory_swap < memory {
        return Err(anyhow!("memory+swap limit should be >= memory limit"));
    }
    Ok(memory_swap - memory)
}
