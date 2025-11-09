use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use libc::pid_t;
use nix::sched::CloneFlags;
use oci_spec::runtime::{self as oci, LinuxDevice, LinuxResources};
use protocols::agent::StatsContainerResponse;
use regex::Regex;
use runtime_spec::{ContainerState, State as OCIState};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::Config;
use crate::process::Process;

type NamespaceType = String;

pub const EXEC_FIFO_FILENAME: &str = "exec.fifo";

pub const INIT: &str = "INIT";
pub const NO_PIVOT: &str = "NO_PIVOT";
pub const CRFD_FD: &str = "CRFD_FD";
pub const CWFD_FD: &str = "CWFD_FD";
pub const CLOG_FD: &str = "CLOG_FD";
pub const FIFO_FD: &str = "FIFO_FD";
pub const HOME_ENV_KEY: &str = "HOME";
pub const PIDNS_FD: &str = "PIDNS_FD";
pub const PIDNS_ENABLED: &str = "PIDNS_ENABLED";
pub const CONSOLE_SOCKET_FD: &str = "CONSOLE_SOCKET_FD";

// Error messages will be warpped with anyhow
pub const MissingLinux: &str = "no linux config";
pub const InvalidNamespace: &str = "invalid namespace type";

#[derive(Debug)]
pub struct ContainerStatus {
    pub(super) pre_status: ContainerState,
    pub(super) cur_status: ContainerState,
}

impl ContainerStatus {
    pub fn new() -> Self {
        ContainerStatus {
            pre_status: ContainerState::Created,
            cur_status: ContainerState::Created,
        }
    }

    pub fn status(&self) -> ContainerState {
        self.cur_status
    }

    pub fn transition(&mut self, to: ContainerState) {
        self.pre_status = self.status();
        self.cur_status = to;
    }
}

impl Default for ContainerStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BaseState {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default)]
    init_process_pid: i32,
    #[serde(default)]
    init_process_start: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    base: BaseState,
    #[serde(default)]
    rootless: bool,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    cgroup_paths: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    namespace_paths: HashMap<NamespaceType, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    external_descriptors: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    intel_rdt_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyncPc {
    #[serde(default)]
    pid: pid_t,
}

#[async_trait]
pub trait BaseContainer {
    fn id(&self) -> String;
    fn status(&self) -> ContainerState;
    fn state(&self) -> Result<State>;
    fn oci_state(&self) -> Result<OCIState>;
    fn config(&self) -> Result<&Config>;
    fn processes(&self) -> Result<Vec<i32>>;
    fn get_process_mut(&mut self, eid: &str) -> Result<&mut Process>;
    fn stats(&self) -> Result<StatsContainerResponse>;
    fn set_resources(&mut self, config: LinuxResources) -> Result<()>;
    async fn start(&mut self, p: Process) -> Result<()>;
    async fn run(&mut self, p: Process) -> Result<()>;
    async fn destroy(&mut self) -> Result<()>;
    async fn exec(&mut self) -> Result<()>;
}

pub trait Container: BaseContainer {
    fn pause(&mut self) -> Result<()>;
    fn resume(&mut self) -> Result<()>;
}

lazy_static! {
    // This locker ensures the child exit signal will be received by the right receiver.
    pub static ref WAIT_PID_LOCKER: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    pub static ref NAMESPACES: HashMap<&'static str, CloneFlags> = {
        let mut m = HashMap::new();
        m.insert("user", CloneFlags::CLONE_NEWUSER);
        m.insert("ipc", CloneFlags::CLONE_NEWIPC);
        m.insert("pid", CloneFlags::CLONE_NEWPID);
        m.insert("net", CloneFlags::CLONE_NEWNET);
        m.insert("mnt", CloneFlags::CLONE_NEWNS);
        m.insert("uts", CloneFlags::CLONE_NEWUTS);
        m.insert("cgroup", CloneFlags::CLONE_NEWCGROUP);
        m
    };

    // type to name hashmap, better to be in NAMESPACES
    pub static ref TYPETONAME: HashMap<oci::LinuxNamespaceType, &'static str> = {
        let mut m = HashMap::new();
        m.insert(oci::LinuxNamespaceType::Ipc, "ipc");
        m.insert(oci::LinuxNamespaceType::User, "user");
        m.insert(oci::LinuxNamespaceType::Pid, "pid");
        m.insert(oci::LinuxNamespaceType::Network, "net");
        m.insert(oci::LinuxNamespaceType::Mount, "mnt");
        m.insert(oci::LinuxNamespaceType::Cgroup, "cgroup");
        m.insert(oci::LinuxNamespaceType::Uts, "uts");
        m
    };

    pub static ref DEFAULT_DEVICES: Vec<LinuxDevice> = {
        vec![
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/null"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(3)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/zero"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(5)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/full"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(7)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/tty"))
                .typ(oci::LinuxDeviceType::C)
                .major(5)
                .minor(0)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/urandom"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(9)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/random"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(8)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
        ]
    };

    pub static ref SYSTEMD_CGROUP_PATH_FORMAT:Regex = Regex::new(r"^[\w\-.]*:[\w\-.]*:[\w\-.]*$").unwrap();
}
