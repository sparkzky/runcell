pub(self) mod namespace;
pub(self) mod types;

use std::{
    collections::HashMap,
    fmt::Display,
    fs::{self, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
    time::SystemTime,
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use cgroups::freezer::FreezerState;
use kata_sys_utils::hooks::HookStates;
use libc::pid_t;
use namespace::setup_child_logger;
use nix::{
    errno::Errno,
    fcntl::{self, FcntlArg, FdFlag, OFlag},
    mount::MntFlags,
    pty,
    sched::{self, CloneFlags},
    sys::{
        signal::{self, Signal},
        stat::{self, Mode},
    },
    unistd::{self, ForkResult, Gid, Pid, Uid, fork},
};
use oci_spec::runtime::{self as oci, LinuxResources};
use protobuf::MessageField;
use protocols::agent::StatsContainerResponse;
use rlimit::{Resource, Rlim, setrlimit};
use runtime_spec::{ContainerState, State as OCIState};
use slog::Logger;
use tokio::fs::File;
pub use types::DEFAULT_DEVICES;
use types::*;

#[cfg(not(test))]
use crate::cgroups::fs::Manager as FsManager;
#[cfg(test)]
use crate::cgroups::mock::Manager as FsManager;
use crate::{
    capabilities,
    cgroups::{CgroupManager, DevicesCgroupInfo},
    container::namespace::{get_namespaces, get_pid_namespace, join_namespaces, update_namespaces},
    log_child, mount,
    pipe::{
        pipestream::PipeStream,
        sync::{SYNC_DATA, SYNC_FAILED, SYNC_SUCCESS, read_sync, write_count, write_sync},
        sync_with_async::read_async,
    },
    process::{Process, ProcessOperations},
    specconf::CreateOpts,
    validator,
};

pub type Config = CreateOpts;

// LinuxContainer protected by Mutex
// Arc<Mutex<Innercontainer>> or just Mutex<InnerContainer>?
// Or use Mutex<xx> as a member of struct, like C?
// a lot of String in the struct might be &str
#[derive(Debug)]
pub struct LinuxContainer {
    pub id: String,
    pub root: String,
    pub config: Config,
    pub cgroup_manager: Box<dyn CgroupManager + Send + Sync>,
    pub init_process_pid: pid_t,
    pub init_process_start_time: u64,
    pub uid_map_path: String,
    pub gid_map_path: String,
    pub processes: HashMap<String, Process>,
    pub status: ContainerStatus,
    pub created: SystemTime,
    pub logger: Logger,
    #[cfg(feature = "standard-oci-runtime")]
    pub console_socket: PathBuf,
}

#[async_trait]
impl BaseContainer for LinuxContainer {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn status(&self) -> ContainerState {
        self.status.status()
    }

    fn state(&self) -> Result<State> {
        Err(anyhow!("not supported"))
    }

    fn oci_state(&self) -> Result<OCIState> {
        let oci = match self.config.spec.as_ref() {
            Some(s) => s,
            None => return Err(anyhow!("Unable to get OCI state: spec not found")),
        };

        let status = self.status();
        let pid = if status != ContainerState::Stopped {
            self.init_process_pid
        } else {
            0
        };

        let root = match oci.root().as_ref() {
            Some(s) => s.path().display().to_string(),
            None => return Err(anyhow!("Unable to get root path: oci.root is none")),
        };

        let path = fs::canonicalize(root)?;
        let bundle = match path.parent() {
            Some(s) => s.to_str().unwrap().to_string(),
            None => return Err(anyhow!("could not get root parent: root path {:?}", path)),
        };

        Ok(OCIState {
            version: oci.version().clone(),
            id: self.id(),
            status,
            pid,
            bundle,
            annotations: oci.annotations().clone().unwrap_or_default(),
        })
    }

    fn config(&self) -> Result<&Config> {
        Ok(&self.config)
    }

    fn processes(&self) -> Result<Vec<i32>> {
        Ok(self.processes.values().map(|p| p.pid).collect())
    }

    fn get_process_mut(&mut self, eid: &str) -> Result<&mut Process> {
        self.processes
            .get_mut(eid)
            .ok_or_else(|| anyhow!("invalid eid {}", eid))
    }

    fn stats(&self) -> Result<StatsContainerResponse> {
        // what about network interface stats?

        Ok(StatsContainerResponse {
            cgroup_stats: MessageField::some(self.cgroup_manager.as_ref().get_stats()?),
            ..Default::default()
        })
    }

    fn set_resources(&mut self, r: LinuxResources) -> Result<()> {
        self.cgroup_manager.as_ref().set(&r, true)?;

        if let Some(linux) = self.config.spec.as_mut().unwrap().linux_mut() {
            linux.set_resources(Some(r));
        }

        Ok(())
    }

    async fn start(&mut self, mut p: Process) -> Result<()> {
        let logger = self.logger.new(o!("eid" => p.exec_id.clone()));

        // Check if exec_id is already in use to prevent collisions
        if self.processes.contains_key(p.exec_id.as_str()) {
            return Err(anyhow!("exec_id '{}' already exists", p.exec_id));
        }

        let tty = p.tty;
        let fifo_file = format!("{}/{}", &self.root, EXEC_FIFO_FILENAME);
        info!(logger, "enter container.start!");
        let mut fifofd: RawFd = -1;
        if p.init {
            if stat::stat(fifo_file.as_str()).is_ok() {
                return Err(anyhow!("exec fifo exists"));
            }
            unistd::mkfifo(fifo_file.as_str(), Mode::from_bits(0o644).unwrap())?;

            fifofd = fcntl::open(
                fifo_file.as_str(),
                OFlag::O_PATH,
                Mode::from_bits(0).unwrap(),
            )?;
        }
        info!(logger, "exec fifo opened!");

        if self.config.spec.is_none() {
            return Err(anyhow!("no spec"));
        }

        let spec = self.config.spec.as_ref().unwrap();
        if spec.linux().is_none() {
            return Err(anyhow!("no linux config"));
        }
        let linux = spec.linux().as_ref().unwrap();

        if p.oci.capabilities().is_none() {
            // No capabilities, inherit from container process
            let process = spec
                .process()
                .as_ref()
                .ok_or_else(|| anyhow!("no process config"))?;
            p.oci.set_capabilities(Some(
                process
                    .capabilities()
                    .clone()
                    .ok_or_else(|| anyhow!("missing process capabilities"))?,
            ));
        }

        let (pfd_log, cfd_log) = unistd::pipe().context("failed to create pipe")?;

        let _ = fcntl::fcntl(pfd_log, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|e| warn!(logger, "fcntl pfd log FD_CLOEXEC {:?}", e));

        let child_logger = logger.new(o!("action" => "child process log"));
        let log_handler = setup_child_logger(pfd_log, child_logger);

        let (prfd, cwfd) = unistd::pipe().context("failed to create pipe")?;
        let (crfd, pwfd) = unistd::pipe().context("failed to create pipe")?;

        let _ = fcntl::fcntl(prfd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|e| warn!(logger, "fcntl prfd FD_CLOEXEC {:?}", e));

        let _ = fcntl::fcntl(pwfd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|e| warn!(logger, "fcntl pwfd FD_COLEXEC {:?}", e));

        let mut pipe_r = PipeStream::from_fd(prfd);
        let mut pipe_w = PipeStream::from_fd(pwfd);

        let child_stdin: std::process::Stdio;
        let child_stdout: std::process::Stdio;
        let child_stderr: std::process::Stdio;

        if tty {
            let pseudo = pty::openpty(None, None)?;
            p.term_master = Some(pseudo.master);
            let _ = fcntl::fcntl(pseudo.master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
                .map_err(|e| warn!(logger, "fnctl pseudo.master {:?}", e));
            let _ = fcntl::fcntl(pseudo.slave, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
                .map_err(|e| warn!(logger, "fcntl pseudo.slave {:?}", e));

            child_stdin = unsafe { std::process::Stdio::from_raw_fd(pseudo.slave) };
            child_stdout = unsafe { std::process::Stdio::from_raw_fd(unistd::dup(pseudo.slave)?) };
            child_stderr = unsafe { std::process::Stdio::from_raw_fd(unistd::dup(pseudo.slave)?) };

            if let Some(proc_io) = &mut p.proc_io {
                // A reference count used to clean up the term master fd.
                let term_closer = Arc::from(unsafe { File::from_raw_fd(pseudo.master) });

                // Copy from stdin to term_master
                if let Some(mut stdin_stream) = proc_io.stdin.take() {
                    let mut term_master = unsafe { File::from_raw_fd(pseudo.master) };
                    let logger = logger.clone();
                    let term_closer = term_closer.clone();
                    tokio::spawn(async move {
                        let res = tokio::io::copy(&mut stdin_stream, &mut term_master).await;
                        debug!(logger, "copy from stdin to term_master end: {:?}", res);

                        std::mem::forget(term_master); // Avoid auto closing of term_master
                        drop(term_closer);
                    });
                }

                // Copy from term_master to stdout
                if let Some(mut stdout_stream) = proc_io.stdout.take() {
                    let wgw_output = proc_io.wg_output.worker();
                    let mut term_master = unsafe { File::from_raw_fd(pseudo.master) };
                    let logger = logger.clone();
                    let term_closer = term_closer;
                    tokio::spawn(async move {
                        let res = tokio::io::copy(&mut term_master, &mut stdout_stream).await;
                        debug!(logger, "copy from term_master to stdout end: {:?}", res);
                        wgw_output.done();
                        std::mem::forget(term_master); // Avoid auto closing of term_master
                        drop(term_closer);
                    });
                }
            }
        } else {
            let stdin = p.stdin.unwrap();
            let stdout = p.stdout.unwrap();
            let stderr = p.stderr.unwrap();
            child_stdin = unsafe { std::process::Stdio::from_raw_fd(stdin) };
            child_stdout = unsafe { std::process::Stdio::from_raw_fd(stdout) };
            child_stderr = unsafe { std::process::Stdio::from_raw_fd(stderr) };

            if let Some(proc_io) = &mut p.proc_io {
                // Here we copy from vsock stdin stream to parent_stdin manually.
                // This is because we need to close the stdin fifo when the stdin stream
                // is drained.
                if let Some(mut stdin_stream) = proc_io.stdin.take() {
                    debug!(logger, "copy from stdin to parent_stdin");
                    let mut parent_stdin = unsafe { File::from_raw_fd(p.parent_stdin.unwrap()) };
                    let logger = logger.clone();
                    tokio::spawn(async move {
                        let res = tokio::io::copy(&mut stdin_stream, &mut parent_stdin).await;
                        debug!(logger, "copy from stdin to term_master end: {:?}", res);
                    });
                }

                // copy from parent_stdout to stdout stream
                if let Some(mut stdout_stream) = proc_io.stdout.take() {
                    debug!(logger, "copy from parent_stdout to stdout stream");
                    let wgw_output = proc_io.wg_output.worker();
                    let mut parent_stdout = unsafe { File::from_raw_fd(p.parent_stdout.unwrap()) };
                    let logger = logger.clone();
                    tokio::spawn(async move {
                        let res = tokio::io::copy(&mut parent_stdout, &mut stdout_stream).await;
                        debug!(
                            logger,
                            "copy from parent_stdout to stdout stream end: {:?}", res
                        );
                        wgw_output.done();
                    });
                }

                // copy from parent_stderr to stderr stream
                if let Some(mut stderr_stream) = proc_io.stderr.take() {
                    debug!(logger, "copy from parent_stderr to stderr stream");
                    let wgw_output = proc_io.wg_output.worker();
                    let mut parent_stderr = unsafe { File::from_raw_fd(p.parent_stderr.unwrap()) };
                    let logger = logger.clone();
                    tokio::spawn(async move {
                        let res = tokio::io::copy(&mut parent_stderr, &mut stderr_stream).await;
                        debug!(
                            logger,
                            "copy from parent_stderr to stderr stream end: {:?}", res
                        );
                        wgw_output.done();
                    });
                }
            }
        }

        let pidns = get_pid_namespace(&self.logger, linux)?;
        #[cfg(not(feature = "standard-oci-runtime"))]
        if !pidns.enabled {
            return Err(anyhow!("cannot find the pid ns"));
        }

        defer!(if let Some(fd) = pidns.fd {
            let _ = unistd::close(fd);
        });

        let exec_path = std::env::current_exe()?;
        let mut child = std::process::Command::new(exec_path);

        #[allow(unused_mut)]
        let mut console_name = PathBuf::from("");
        #[cfg(feature = "standard-oci-runtime")]
        if !self.console_socket.as_os_str().is_empty() {
            console_name = self.console_socket.clone();
        }

        let mut child = child
            .arg("init")
            .stdin(child_stdin)
            .stdout(child_stdout)
            .stderr(child_stderr)
            .env(INIT, format!("{}", p.init))
            .env(NO_PIVOT, format!("{}", self.config.no_pivot_root))
            .env(CRFD_FD, format!("{}", crfd))
            .env(CWFD_FD, format!("{}", cwfd))
            .env(CLOG_FD, format!("{}", cfd_log))
            .env(CONSOLE_SOCKET_FD, console_name)
            .env(PIDNS_ENABLED, format!("{}", pidns.enabled));

        if p.init {
            child = child.env(FIFO_FD, format!("{}", fifofd));
        }

        if pidns.fd.is_some() {
            child = child.env(PIDNS_FD, format!("{}", pidns.fd.unwrap()));
        }

        child.spawn()?;

        unistd::close(crfd)?;
        unistd::close(cwfd)?;
        unistd::close(cfd_log)?;

        // get container process's pid
        let pid_buf = read_async(&mut pipe_r).await?;
        let pid_str = std::str::from_utf8(&pid_buf).context("get pid string")?;
        let pid = match pid_str.parse::<i32>() {
            Ok(i) => i,
            Err(e) => {
                return Err(anyhow!(format!(
                    "failed to get container process's pid: {:?}",
                    e
                )));
            }
        };

        p.pid = pid;

        if p.init {
            self.init_process_pid = p.pid;
        }

        if p.init {
            let _ = unistd::close(fifofd).map_err(|e| warn!(logger, "close fifofd {:?}", e));
        }

        info!(logger, "child pid: {}", p.pid);

        let st = self.oci_state()?;

        join_namespaces(
            &logger,
            spec,
            &p,
            self.cgroup_manager.as_ref(),
            self.config.use_systemd_cgroup,
            &st,
            &mut pipe_w,
            &mut pipe_r,
        )
        .await
        .map_err(|e| {
            error!(logger, "create container process error {:?}", e);
            // kill the child process.
            let _ = signal::kill(Pid::from_raw(p.pid), Some(Signal::SIGKILL))
                .map_err(|e| warn!(logger, "signal::kill joining namespaces {:?}", e));

            e
        })?;

        info!(logger, "entered namespaces!");

        if p.init {
            let spec = self.config.spec.as_mut().unwrap();
            update_namespaces(&self.logger, spec, p.pid)?;
        }
        self.processes.insert(p.exec_id.clone(), p);

        info!(logger, "wait on child log handler");
        let _ = log_handler
            .await
            .map_err(|e| warn!(logger, "joining log handler {:?}", e));
        info!(logger, "create process completed");

        Ok(())
    }

    async fn run(&mut self, p: Process) -> Result<()> {
        let init = p.init;
        self.start(p).await?;

        if init {
            self.exec().await?;
            self.status.transition(ContainerState::Running);
        }

        Ok(())
    }

    async fn destroy(&mut self) -> Result<()> {
        let spec = self.config.spec.as_ref().unwrap();
        let st = self.oci_state()?;

        for process in self.processes.values() {
            match signal::kill(process.pid(), Some(Signal::SIGKILL)) {
                Err(Errno::ESRCH) => {
                    info!(
                        self.logger,
                        "kill encounters ESRCH, pid: {}, container: {}",
                        process.pid(),
                        self.id.clone()
                    );
                    continue;
                }
                Err(err) => return Err(anyhow!(err)),
                Ok(_) => continue,
            }
        }

        // guest Poststop hook
        // * should be executed after the container is deleted but before the delete
        //   operation returns
        // * the executable file is in agent namespace
        // * should also be executed in agent namespace.
        if let Some(hooks) = spec.hooks().as_ref() {
            info!(self.logger, "guest Poststop hook");
            let mut hook_states = HookStates::new();
            hook_states.execute_hooks(
                hooks.poststop().clone().unwrap_or_default().as_slice(),
                Some(st),
            )?;
        }

        self.status.transition(ContainerState::Stopped);
        mount::umount2(
            spec.root()
                .as_ref()
                .unwrap()
                .path()
                .display()
                .to_string()
                .as_str(),
            MntFlags::MNT_DETACH,
        )
        .or_else(|e| {
            if e.ne(&nix::Error::EINVAL) {
                return Err(anyhow!(e));
            }
            warn!(self.logger, "rootfs not mounted");
            Ok(())
        })?;
        fs::remove_dir_all(&self.root)?;

        let cgm = self.cgroup_manager.as_mut();
        // Kill all of the processes created in this container to prevent
        // the leak of some daemon process when this container shared pidns
        // with the sandbox.
        let pids = cgm.get_pids().context("get cgroup pids")?;
        for i in pids {
            if let Err(e) = signal::kill(Pid::from_raw(i), Signal::SIGKILL) {
                warn!(self.logger, "kill the process {} error: {:?}", i, e);
            }
        }

        cgm.destroy().context("destroy cgroups")?;
        Ok(())
    }

    async fn exec(&mut self) -> Result<()> {
        let fifo = format!("{}/{}", &self.root, EXEC_FIFO_FILENAME);
        let fd = fcntl::open(fifo.as_str(), OFlag::O_WRONLY, Mode::from_bits_truncate(0))?;
        let data: &[u8] = &[0];
        unistd::write(fd, data)?;
        info!(self.logger, "container started");
        self.init_process_start_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.status.transition(ContainerState::Running);

        let spec = self
            .config
            .spec
            .as_ref()
            .ok_or_else(|| anyhow!("OCI spec was not found"))?;
        let st = self.oci_state()?;

        // guest Poststart hook
        // * should be executed after the container is started but before the delete
        //   operation returns
        // * the executable file is in agent namespace
        // * should also be executed in agent namespace.
        if let Some(hooks) = spec.hooks().as_ref() {
            info!(self.logger, "guest Poststart hook");
            let mut hook_states = HookStates::new();
            hook_states.execute_hooks(
                hooks.poststart().clone().unwrap_or_default().as_slice(),
                Some(st),
            )?;
        }

        unistd::close(fd)?;

        Ok(())
    }
}

impl Container for LinuxContainer {
    fn pause(&mut self) -> Result<()> {
        let status = self.status();
        if status != ContainerState::Running && status != ContainerState::Created {
            return Err(anyhow!(
                "failed to pause container: current status is: {:?}",
                status
            ));
        }

        self.cgroup_manager.as_ref().freeze(FreezerState::Frozen)?;

        self.status.transition(ContainerState::Paused);

        Ok(())
    }

    fn resume(&mut self) -> Result<()> {
        let status = self.status();
        if status != ContainerState::Paused {
            return Err(anyhow!("container status is: {:?}, not paused", status));
        }

        self.cgroup_manager.as_ref().freeze(FreezerState::Thawed)?;

        self.status.transition(ContainerState::Running);

        Ok(())
    }
}

impl LinuxContainer {
    pub fn new<T: Into<String> + Display + Clone>(
        id: T,
        base: T,
        devcg_info: Option<Arc<RwLock<DevicesCgroupInfo>>>,
        config: Config,
        logger: &Logger,
    ) -> Result<Self> {
        let base = base.into();
        let id = id.into();
        let root = format!("{}/{}", base.as_str(), id.as_str());

        // validate oci spec
        validator::validate(&config)?;

        fs::create_dir_all(root.as_str()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                return anyhow!(e).context(format!("container {} already exists", id.as_str()));
            }

            anyhow!(e).context(format!("fail to create container directory {}", root))
        })?;

        unistd::chown(
            root.as_str(),
            Some(unistd::getuid()),
            Some(unistd::getgid()),
        )
        .context(format!("Cannot change owner of container {} root", id))?;

        let spec = config.spec.as_ref().unwrap();
        let linux_cgroups_path = spec
            .linux()
            .as_ref()
            .unwrap()
            .cgroups_path()
            .as_ref()
            .map_or(String::new(), |cgrp| cgrp.display().to_string());
        let cpath = if config.use_systemd_cgroup {
            if linux_cgroups_path.len() == 2 {
                format!("system.slice:kata_agent:{}", id.as_str())
            } else {
                linux_cgroups_path.clone()
            }
        } else if linux_cgroups_path.is_empty() {
            format!("/{}", id.as_str())
        } else {
            // if we have a systemd cgroup path we need to convert it to a fs cgroup path
            linux_cgroups_path.replace(':', "/")
        };

        let cgroup_manager: Box<dyn CgroupManager + Send + Sync> = if config.use_systemd_cgroup {
            todo!("systemd cgroup manager is not supported yet")
        } else {
            Box::new(
                FsManager::new(cpath.as_str(), spec, devcg_info)
                    .context("Create cgroupfs manager")?,
            )
        };
        info!(logger, "new cgroup_manager {:?}", &cgroup_manager);

        Ok(LinuxContainer {
            id: id.clone(),
            root,
            cgroup_manager,
            status: ContainerStatus::new(),
            uid_map_path: String::from(""),
            gid_map_path: "".to_string(),
            config,
            processes: HashMap::new(),
            created: SystemTime::now(),
            init_process_pid: -1,
            init_process_start_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            logger: logger.new(o!("module" => "rustjail", "subsystem" => "container", "cid" => id)),
            #[cfg(feature = "standard-oci-runtime")]
            console_socket: Path::new("").to_path_buf(),
        })
    }

    #[cfg(feature = "standard-oci-runtime")]
    pub fn set_console_socket(&mut self, console_socket: &Path) -> Result<()> {
        self.console_socket = console_socket.to_path_buf();
        Ok(())
    }
}

fn setid(uid: Uid, gid: Gid) -> Result<()> {
    // set uid/gid
    capctl::prctl::set_keepcaps(true)
        .map_err(|e| anyhow!(e).context("set keep capabilities returned"))?;

    {
        unistd::setresgid(gid, gid, gid)?;
    }
    {
        unistd::setresuid(uid, uid, uid)?;
    }
    // if we change from zero, we lose effective caps
    if uid != Uid::from_raw(0) {
        capabilities::reset_effective()?;
    }

    capctl::prctl::set_keepcaps(false)
        .map_err(|e| anyhow!(e).context("set keep capabilities returned"))?;

    Ok(())
}

fn set_sysctls(sysctls: &HashMap<String, String>) -> Result<()> {
    for (key, value) in sysctls {
        let name = format!("/proc/sys/{}", key.replace('.', "/"));
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(name.as_str())
        {
            Ok(f) => f,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    continue;
                }
                return Err(e.into());
            }
        };

        file.write_all(value.as_bytes())?;
    }

    Ok(())
}

pub fn init_child() {
    let cwfd = std::env::var(CWFD_FD).unwrap().parse::<i32>().unwrap();
    let cfd_log = std::env::var(CLOG_FD).unwrap().parse::<i32>().unwrap();

    match do_init_child(cwfd) {
        Ok(_) => log_child!(cfd_log, "temporary parent process exit successfully"),
        Err(e) => {
            log_child!(cfd_log, "temporary parent process exit:child exit: {:?}", e);
            let _ = write_sync(cwfd, SYNC_FAILED, format!("{:?}", e).as_str());
        }
    }
}

fn do_init_child(cwfd: RawFd) -> Result<()> {
    lazy_static::initialize(&NAMESPACES);
    lazy_static::initialize(&DEFAULT_DEVICES);

    let init = std::env::var(INIT)?.eq(format!("{}", true).as_str());

    let no_pivot = std::env::var(NO_PIVOT)?.eq(format!("{}", true).as_str());
    let crfd = std::env::var(CRFD_FD)?.parse::<i32>().unwrap();
    let cfd_log = std::env::var(CLOG_FD)?.parse::<i32>().unwrap();

    if std::env::var(PIDNS_ENABLED)?.eq(format!("{}", true).as_str()) {
        // get the pidns fd from parent, if parent had passed the pidns fd,
        // then get it and join in this pidns; otherwise, create a new pidns
        // by unshare from the parent pidns.
        match std::env::var(PIDNS_FD) {
            Ok(fd) => {
                let pidns_fd = fd.parse::<i32>().context("get parent pidns fd")?;
                sched::setns(pidns_fd, CloneFlags::CLONE_NEWPID).context("failed to join pidns")?;
                let _ = unistd::close(pidns_fd);
            }
            Err(_e) => {
                sched::unshare(CloneFlags::CLONE_NEWPID)?;
            }
        }
    }

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            log_child!(
                cfd_log,
                "Continuing execution in temporary process, new child has pid: {:?}",
                child
            );
            let _ = write_sync(cwfd, SYNC_DATA, format!("{}", pid_t::from(child)).as_str());
            // parent return
            return Ok(());
        }
        Ok(ForkResult::Child) => (),
        Err(e) => {
            return Err(anyhow!(format!(
                "failed to fork temporary process: {:?}",
                e
            )));
        }
    }

    log_child!(cfd_log, "child process start run");
    let buf = read_sync(crfd)?;
    let spec_str = std::str::from_utf8(&buf)?;
    let spec: oci::Spec = serde_json::from_str(spec_str)?;
    log_child!(cfd_log, "notify parent to send oci process");
    write_sync(cwfd, SYNC_SUCCESS, "")?;

    let buf = read_sync(crfd)?;
    let process_str = std::str::from_utf8(&buf)?;
    let oci_process: oci::Process = serde_json::from_str(process_str)?;
    log_child!(cfd_log, "notify parent to send oci state");
    write_sync(cwfd, SYNC_SUCCESS, "")?;

    let buf = read_sync(crfd)?;
    let state_str = std::str::from_utf8(&buf)?;
    let mut state: OCIState = serde_json::from_str(state_str)?;
    log_child!(cfd_log, "notify parent to send cgroup manager");
    write_sync(cwfd, SYNC_SUCCESS, "")?;

    let buf = read_sync(crfd)?;
    let cm_str = std::str::from_utf8(&buf)?;

    // deserialize cm_str into FsManager and SystemdManager separately
    let fs_cm: Result<FsManager, serde_json::Error> = serde_json::from_str(cm_str);
    // let systemd_cm: Result<SystemdManager, serde_json::Error> =
    // serde_json::from_str(cm_str);

    #[cfg(feature = "standard-oci-runtime")]
    let csocket_fd = console::setup_console_socket(&std::env::var(CONSOLE_SOCKET_FD)?)?;

    let p = if spec.process().is_some() {
        spec.process().as_ref().unwrap()
    } else {
        return Err(anyhow!("didn't find process in Spec"));
    };

    if spec.linux().is_none() {
        return Err(anyhow!(MissingLinux));
    }
    let linux = spec.linux().as_ref().unwrap();

    // get namespace vector to join/new
    let nses = get_namespaces(linux);

    let mut userns = false;
    let mut to_new = CloneFlags::empty();
    let mut to_join = Vec::new();

    for ns in &nses {
        let ns_type = ns.typ().to_string();
        let s = NAMESPACES.get(&ns_type.as_str());
        if s.is_none() {
            return Err(anyhow!(InvalidNamespace));
        }
        let s = s.unwrap();

        if ns.path().as_ref().is_none_or(|p| p.as_os_str().is_empty()) {
            // skip the pidns since it has been done in parent process.
            if *s != CloneFlags::CLONE_NEWPID {
                to_new.set(*s, true);
            }
        } else {
            let fd = fcntl::open(ns.path().as_ref().unwrap(), OFlag::O_CLOEXEC, Mode::empty())
                .inspect_err(|e| {
                    log_child!(
                        cfd_log,
                        "cannot open type: {} path: {}",
                        &ns.typ().to_string(),
                        ns.path().as_ref().unwrap().display()
                    );
                    log_child!(cfd_log, "error is : {:?}", e)
                })?;

            if *s != CloneFlags::CLONE_NEWPID {
                to_join.push((*s, fd));
            }
        }
    }

    if to_new.contains(CloneFlags::CLONE_NEWUSER) {
        userns = true;
    }

    if p.oom_score_adj().is_some() {
        log_child!(cfd_log, "write oom score {}", p.oom_score_adj().unwrap());
        fs::write(
            "/proc/self/oom_score_adj",
            p.oom_score_adj().unwrap().to_string().as_bytes(),
        )?;
    }

    // set rlimit
    let default_rlimits = Vec::new();
    let process_rlimits = p.rlimits().as_ref().unwrap_or(&default_rlimits);
    for rl in process_rlimits.iter() {
        log_child!(cfd_log, "set resource limit: {:?}", rl);
        setrlimit(
            Resource::from_str(&rl.typ().to_string())?,
            Rlim::from_raw(rl.soft()),
            Rlim::from_raw(rl.hard()),
        )?;
    }

    // Make the process non-dumpable, to avoid various race conditions that
    // could cause processes in namespaces we're joining to access host
    // resources (or potentially execute code).
    //
    // However, if the number of namespaces we are joining is 0, we are not
    // going to be switching to a different security context. Thus setting
    // ourselves to be non-dumpable only breaks things (like rootless
    // containers), which is the recommendation from the kernel folks.
    //
    // Ref: https://github.com/opencontainers/runc/commit/50a19c6ff828c58e5dab13830bd3dacde268afe5
    //
    if !nses.is_empty() {
        capctl::prctl::set_dumpable(false)
            .map_err(|e| anyhow!(e).context("set process non-dumpable failed"))?;
    }

    if userns {
        log_child!(cfd_log, "enter new user namespace");
        sched::unshare(CloneFlags::CLONE_NEWUSER)?;
    }

    log_child!(cfd_log, "notify parent unshare user ns completed");
    // notify parent unshare user ns completed.
    write_sync(cwfd, SYNC_SUCCESS, "")?;
    // wait parent to setup user id mapping.
    log_child!(cfd_log, "wait parent to setup user id mapping");
    read_sync(crfd)?;

    Ok(())
}

// set_stdio_permissions fixes the permissions of PID 1's STDIO
// within the container to the specified user.
// The ownership needs to match because it is created outside of
// the container and needs to be localized.
fn set_stdio_permissions(uid: Uid) -> Result<()> {
    let meta = fs::metadata("/dev/null")?;
    let fds = [
        std::io::stdin().as_raw_fd(),
        std::io::stdout().as_raw_fd(),
        std::io::stderr().as_raw_fd(),
    ];

    for fd in &fds {
        let stat = stat::fstat(*fd)?;
        // Skip chown of /dev/null if it was used as one of the STDIO fds.
        if stat.st_rdev == meta.rdev() {
            continue;
        }

        // We only change the uid owner (as it is possible for the mount to
        // prefer a different gid, and there's no reason for us to change it).
        // The reason why we don't just leave the default uid=X mount setup is
        // that users expect to be able to actually use their console. Without
        // this code, you couldn't effectively run as a non-root user inside a
        // container and also have a console set up.
        unistd::fchown(*fd, Some(uid), None).with_context(|| "set stdio permissions failed")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{fs::MetadataExt, io::AsRawFd},
        time::UNIX_EPOCH,
    };

    use nix::unistd::Uid;
    use oci::{LinuxBuilder, LinuxDeviceCgroupBuilder, LinuxResourcesBuilder, Root, SpecBuilder};
    use oci_spec::runtime::{self as oci, Spec};
    use tempfile::tempdir;
    use test_utils::skip_if_not_root;

    use super::*;
    use crate::process::Process;

    const CGROUP_PARENT: &str = "kata.agent.test.k8s.io";

    fn sl() -> slog::Logger {
        slog_scope::logger()
    }

    #[test]
    fn test_status_transtition() {
        let mut status = ContainerStatus::new();
        let status_table: [ContainerState; 4] = [
            ContainerState::Created,
            ContainerState::Running,
            ContainerState::Paused,
            ContainerState::Stopped,
        ];

        for s in status_table.iter() {
            let pre_status = status.status();
            status.transition(*s);

            assert_eq!(pre_status, status.pre_status);
        }
    }

    #[test]
    fn test_set_stdio_permissions() {
        skip_if_not_root!();

        let meta = fs::metadata("/dev/stdin").unwrap();
        let old_uid = meta.uid();

        let uid = 1000;
        set_stdio_permissions(Uid::from_raw(uid)).unwrap();

        let meta = fs::metadata("/dev/stdin").unwrap();
        assert_eq!(meta.uid(), uid);

        let meta = fs::metadata("/dev/stdout").unwrap();
        assert_eq!(meta.uid(), uid);

        let meta = fs::metadata("/dev/stderr").unwrap();
        assert_eq!(meta.uid(), uid);

        // restore the uid
        set_stdio_permissions(Uid::from_raw(old_uid)).unwrap();
    }

    #[test]
    fn test_namespaces() {
        lazy_static::initialize(&NAMESPACES);
        assert_eq!(NAMESPACES.len(), 7);

        let ns = NAMESPACES.get("user");
        assert!(ns.is_some());

        let ns = NAMESPACES.get("ipc");
        assert!(ns.is_some());

        let ns = NAMESPACES.get("pid");
        assert!(ns.is_some());

        let ns = NAMESPACES.get("net");
        assert!(ns.is_some());

        let ns = NAMESPACES.get("mnt");
        assert!(ns.is_some());

        let ns = NAMESPACES.get("uts");
        assert!(ns.is_some());

        let ns = NAMESPACES.get("cgroup");
        assert!(ns.is_some());
    }

    #[test]
    fn test_typetoname() {
        lazy_static::initialize(&TYPETONAME);
        assert_eq!(TYPETONAME.len(), 7);

        let ns = TYPETONAME.get(&oci::LinuxNamespaceType::User);
        assert!(ns.is_some());

        let ns = TYPETONAME.get(&oci::LinuxNamespaceType::Ipc);
        assert!(ns.is_some());

        let ns = TYPETONAME.get(&oci::LinuxNamespaceType::Pid);
        assert!(ns.is_some());

        let ns = TYPETONAME.get(&oci::LinuxNamespaceType::Network);
        assert!(ns.is_some());

        let ns = TYPETONAME.get(&oci::LinuxNamespaceType::Mount);
        assert!(ns.is_some());

        let ns = TYPETONAME.get(&oci::LinuxNamespaceType::Uts);
        assert!(ns.is_some());

        let ns = TYPETONAME.get(&oci::LinuxNamespaceType::Cgroup);
        assert!(ns.is_some());
    }

    fn create_dummy_opts() -> CreateOpts {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let mut root = Root::default();
        root.set_path(String::from("/tmp").into());

        let linux_resources = LinuxResourcesBuilder::default()
            .devices(vec![
                LinuxDeviceCgroupBuilder::default()
                    .allow(true)
                    .typ(oci::LinuxDeviceType::C)
                    .access("rwm")
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();

        let cgroups_path = format!(
            "/{}/dummycontainer{}",
            CGROUP_PARENT,
            since_the_epoch.as_micros()
        );

        let mut spec = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .cgroups_path(cgroups_path)
                    .resources(linux_resources)
                    .build()
                    .unwrap(),
            )
            .root(root)
            .build()
            .unwrap();
        spec.set_process(None);

        CreateOpts {
            cgroup_name: "".to_string(),
            use_systemd_cgroup: false,
            no_pivot_root: false,
            no_new_keyring: false,
            spec: Some(spec),
            rootless_euid: false,
            rootless_cgroup: false,
            container_name: "".to_string(),
        }
    }

    fn new_linux_container() -> (Result<LinuxContainer>, tempfile::TempDir) {
        // Create a temporal directory
        let dir = tempdir()
            .map_err(|e| anyhow!(e).context("tempdir failed"))
            .unwrap();

        // Create a new container
        (
            LinuxContainer::new(
                "some_id",
                &dir.path().join("rootfs").to_str().unwrap(),
                None,
                create_dummy_opts(),
                &slog_scope::logger(),
            ),
            dir,
        )
    }

    fn new_linux_container_and_then<U, F: FnOnce(LinuxContainer) -> Result<U, anyhow::Error>>(
        op: F,
    ) -> Result<U, anyhow::Error> {
        let (container, _dir) = new_linux_container();
        container.and_then(op)
    }

    #[test]
    fn test_linuxcontainer_pause_bad_status() {
        let ret = new_linux_container_and_then(|mut c: LinuxContainer| {
            // Change state to pause, c.pause() should fail
            c.status.transition(ContainerState::Paused);
            c.pause().map_err(|e| anyhow!(e))
        });

        assert!(ret.is_err(), "Expecting error, Got {:?}", ret);
        assert!(format!("{:?}", ret).contains("failed to pause container"))
    }

    #[test]
    fn test_linuxcontainer_pause() {
        let ret = new_linux_container_and_then(|mut c: LinuxContainer| {
            c.cgroup_manager =
                Box::new(FsManager::new("", &Spec::default(), None).map_err(|e| {
                    anyhow!(format!("fail to create cgroup manager with path: {:}", e))
                })?);
            c.pause().map_err(|e| anyhow!(e))
        });

        assert!(ret.is_ok(), "Expecting Ok, Got {:?}", ret);
    }

    #[test]
    fn test_linuxcontainer_resume_bad_status() {
        let ret = new_linux_container_and_then(|mut c: LinuxContainer| {
            // Change state to created, c.resume() should fail
            c.status.transition(ContainerState::Created);
            c.resume().map_err(|e| anyhow!(e))
        });

        assert!(ret.is_err(), "Expecting error, Got {:?}", ret);
        assert!(format!("{:?}", ret).contains("not paused"))
    }

    #[test]
    fn test_linuxcontainer_resume() {
        let ret = new_linux_container_and_then(|mut c: LinuxContainer| {
            c.cgroup_manager =
                Box::new(FsManager::new("", &Spec::default(), None).map_err(|e| {
                    anyhow!(format!("fail to create cgroup manager with path: {:}", e))
                })?);
            // Change status to paused, this way we can resume it
            c.status.transition(ContainerState::Paused);
            c.resume().map_err(|e| anyhow!(e))
        });

        assert!(ret.is_ok(), "Expecting Ok, Got {:?}", ret);
    }

    #[test]
    fn test_linuxcontainer_state() {
        let ret = new_linux_container_and_then(|c: LinuxContainer| c.state());
        assert!(ret.is_err(), "Expecting Err, Got {:?}", ret);
        assert!(
            format!("{:?}", ret).contains("not supported"),
            "Got: {:?}",
            ret
        )
    }

    #[test]
    fn test_linuxcontainer_oci_state_no_root_parent() {
        let ret = new_linux_container_and_then(|mut c: LinuxContainer| {
            c.config
                .spec
                .as_mut()
                .unwrap()
                .root_mut()
                .as_mut()
                .unwrap()
                .set_path("/".to_string().into());
            c.oci_state()
        });
        assert!(ret.is_err(), "Expecting Err, Got {:?}", ret);
        assert!(
            format!("{:?}", ret).contains("could not get root parent"),
            "Got: {:?}",
            ret
        )
    }

    #[test]
    fn test_linuxcontainer_oci_state() {
        let ret = new_linux_container_and_then(|c: LinuxContainer| c.oci_state());
        assert!(ret.is_ok(), "Expecting Ok, Got {:?}", ret);
    }

    #[test]
    fn test_linuxcontainer_config() {
        let ret = new_linux_container_and_then(|c: LinuxContainer| Ok(c));
        assert!(ret.is_ok(), "Expecting ok, Got {:?}", ret);
        assert!(
            ret.as_ref().unwrap().config().is_ok(),
            "Expecting ok, Got {:?}",
            ret
        );
    }

    #[test]
    fn test_linuxcontainer_processes() {
        let ret = new_linux_container_and_then(|c: LinuxContainer| c.processes());
        assert!(ret.is_ok(), "Expecting Ok, Got {:?}", ret);
    }

    #[test]
    fn test_linuxcontainer_get_process_not_found() {
        let _ = new_linux_container_and_then(|mut c: LinuxContainer| {
            let p = c.get_process_mut("123");
            assert!(p.is_err(), "Expecting Err, Got {:?}", p);
            Ok(())
        });
    }

    #[tokio::test]
    async fn test_linuxcontainer_get_process() {
        let _ = new_linux_container_and_then(|mut c: LinuxContainer| {
            let process =
                Process::new(&sl(), &oci::Process::default(), "123", true, 1, None).unwrap();
            let exec_id = process.exec_id.clone();
            c.processes.insert(exec_id, process);

            let p = c.get_process_mut("123");
            assert!(p.is_ok(), "Expecting Ok, Got {:?}", p);
            Ok(())
        });
    }

    #[test]
    fn test_linuxcontainer_stats() {
        let ret = new_linux_container_and_then(|c: LinuxContainer| c.stats());
        assert!(ret.is_ok(), "Expecting Ok, Got {:?}", ret);
    }

    #[test]
    fn test_linuxcontainer_set() {
        let ret = new_linux_container_and_then(|mut c: LinuxContainer| {
            c.set_resources(oci::LinuxResources::default())
        });
        assert!(ret.is_ok(), "Expecting Ok, Got {:?}", ret);
    }

    #[tokio::test]
    async fn test_linuxcontainer_start() {
        let (c, _dir) = new_linux_container();
        let mut oci_process = oci::Process::default();
        oci_process.set_capabilities(None);
        let ret = c
            .unwrap()
            .start(Process::new(&sl(), &oci_process, "123", true, 1, None).unwrap())
            .await;
        assert!(format!("{:?}", ret).contains("no process config"));
    }

    #[tokio::test]
    async fn test_linuxcontainer_run() {
        let (c, _dir) = new_linux_container();
        let mut oci_process = oci::Process::default();
        oci_process.set_capabilities(None);
        let ret = c
            .unwrap()
            .run(Process::new(&sl(), &oci_process, "123", true, 1, None).unwrap())
            .await;
        assert!(format!("{:?}", ret).contains("no process config"));
    }

    #[tokio::test]
    async fn test_linuxcontainer_destroy() {
        let (c, _dir) = new_linux_container();

        let ret = c.unwrap().destroy().await;
        assert!(ret.is_ok(), "Expecting Ok, Got {:?}", ret);
    }

    #[tokio::test]
    async fn test_linuxcontainer_exec() {
        let (c, _dir) = new_linux_container();
        let ret = c.unwrap().exec().await;
        assert!(ret.is_err(), "Expecting Err, Got {:?}", ret);
    }

    #[test]
    fn test_linuxcontainer_do_init_child() {
        let ret = do_init_child(std::io::stdin().as_raw_fd());
        assert!(ret.is_err(), "Expecting Err, Got {:?}", ret);
    }
}
