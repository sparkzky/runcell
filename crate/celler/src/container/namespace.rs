use std::{os::fd::RawFd, path::PathBuf};

use anyhow::{Result, anyhow};
use kata_sys_utils::hooks::HookStates;
use nix::{
    fcntl::{self, OFlag},
    sys::stat::Mode,
    unistd,
};
use oci_spec::runtime::{Linux, LinuxIdMapping, LinuxNamespace, Spec};
use runtime_spec::State as OCIState;
use slog::Logger;
use tokio::io::AsyncBufReadExt;

use super::types::TYPETONAME;
#[cfg(not(test))]
use crate::cgroups::fs::Manager as FsManager;
#[cfg(test)]
use crate::cgroups::mock::Manager as FsManager;
use crate::{
    cgroups::CgroupManager,
    pipe::{
        pipestream::PipeStream,
        sync::{SYNC_DATA, SYNC_SUCCESS},
        sync_with_async::{read_async, write_async},
    },
    process::Process,
};

pub fn update_namespaces(logger: &Logger, spec: &mut Spec, init_pid: RawFd) -> Result<()> {
    info!(logger, "updating namespaces for init pid fd {}", init_pid);
    let linux = spec
        .linux_mut()
        .as_mut()
        .ok_or_else(|| anyhow!("Spec didn't contain linux field"))?;

    if let Some(namespaces) = linux.namespaces_mut().as_mut() {
        for namespace in namespaces.iter_mut() {
            if TYPETONAME.contains_key(&namespace.typ()) {
                let ns_path = format!(
                    "/proc/{}/ns/{}",
                    init_pid,
                    TYPETONAME.get(&namespace.typ()).unwrap()
                );

                if namespace
                    .path()
                    .as_ref()
                    .is_none_or(|p| p.as_os_str().is_empty())
                {
                    namespace.set_path(Some(PathBuf::from(&ns_path)));
                }
            }
        }
    }

    Ok(())
}

pub fn get_pid_namespace(logger: &Logger, linux: &Linux) -> Result<PidNs> {
    let linux_namespaces = linux.namespaces().clone().unwrap_or_default();
    for ns in &linux_namespaces {
        if &ns.typ().to_string() == "pid" {
            let fd = match ns.path() {
                None => return Ok(PidNs::new(true, None)),
                Some(ns_path) => fcntl::open(
                    ns_path.display().to_string().as_str(),
                    OFlag::O_RDONLY,
                    Mode::empty(),
                )
                .inspect_err(|e| {
                    error!(
                        logger,
                        "cannot open type: {} path: {}",
                        &ns.typ().to_string(),
                        ns_path.display()
                    );
                    error!(logger, "error is : {:?}", e)
                })?,
            };

            return Ok(PidNs::new(true, Some(fd)));
        }
    }

    Ok(PidNs::new(false, None))
}

fn is_userns_enabled(linux: &Linux) -> bool {
    linux
        .namespaces()
        .clone()
        .unwrap_or_default()
        .iter()
        .any(|ns| &ns.typ().to_string() == "user" && ns.path().is_none())
}

pub(super)fn get_namespaces(linux: &Linux) -> Vec<LinuxNamespace> {
    linux
        .namespaces()
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|ns| {
            let mut namespace = LinuxNamespace::default();
            namespace.set_typ(ns.typ());
            namespace.set_path(ns.path().clone());

            namespace
        })
        .collect()
}

pub fn setup_child_logger(fd: RawFd, child_logger: Logger) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let log_file_stream = PipeStream::from_fd(fd);
        let buf_reader_stream = tokio::io::BufReader::new(log_file_stream);
        let mut lines = buf_reader_stream.lines();

        loop {
            match lines.next_line().await {
                Err(e) => {
                    info!(child_logger, "read child process log error: {:?}", e);
                    break;
                }
                Ok(Some(line)) => {
                    info!(child_logger, "{}", line);
                }
                Ok(None) => {
                    info!(child_logger, "read child process log end",);
                    break;
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn join_namespaces(
    logger: &Logger,
    spec: &Spec,
    p: &Process,
    cm: &(dyn CgroupManager + Send + Sync),
    use_systemd_cgroup: bool,
    st: &OCIState,
    pipe_w: &mut PipeStream,
    pipe_r: &mut PipeStream,
) -> Result<()> {
    let logger = logger.new(o!("action" => "join-namespaces"));

    let linux = spec
        .linux()
        .as_ref()
        .ok_or_else(|| anyhow!("Spec didn't contain linux field"))?;
    let res = linux.resources().as_ref();

    let userns = is_userns_enabled(linux);

    info!(logger, "try to send spec from parent to child");
    let spec_str = serde_json::to_string(spec)?;
    write_async(pipe_w, SYNC_DATA, spec_str.as_str()).await?;

    info!(logger, "wait child received oci spec");
    read_async(pipe_r).await?;

    info!(logger, "send oci process from parent to child");
    let process_str = serde_json::to_string(&p.oci)?;
    write_async(pipe_w, SYNC_DATA, process_str.as_str()).await?;

    info!(logger, "wait child received oci process");
    read_async(pipe_r).await?;

    info!(logger, "try to send state from parent to child");
    let state_str = serde_json::to_string(st)?;
    write_async(pipe_w, SYNC_DATA, state_str.as_str()).await?;

    info!(logger, "wait child received oci state");
    read_async(pipe_r).await?;

    let cm_str = if use_systemd_cgroup {
        todo!("systemd cgroup manager is not supported yet")
    } else {
        serde_json::to_string(cm.as_any()?.downcast_ref::<FsManager>().unwrap())
    }?;
    write_async(pipe_w, SYNC_DATA, cm_str.as_str()).await?;

    // wait child setup user namespace
    info!(logger, "wait child setup user namespace");
    read_async(pipe_r).await?;

    if userns {
        info!(logger, "setup uid/gid mappings");
        let uid_mappings = linux.uid_mappings().clone().unwrap_or_default();
        let gid_mappings = linux.gid_mappings().clone().unwrap_or_default();
        // setup uid/gid mappings
        write_mappings(&logger, &format!("/proc/{}/uid_map", p.pid), &uid_mappings)?;
        write_mappings(&logger, &format!("/proc/{}/gid_map", p.pid), &gid_mappings)?;
    }

    // apply cgroups
    // For FsManger, it's no matter about the order of apply and set.
    // For SystemdManger, apply must be precede set because we can only create a
    // systemd unit with specific processes(pids).
    if res.is_some() {
        info!(logger, "apply processes to cgroups!");
        cm.apply(p.pid)?;
    }

    if p.init && res.is_some() {
        info!(logger, "set properties to cgroups!");
        cm.set(res.unwrap(), false)?;
    }

    info!(logger, "notify child to continue");
    // notify child to continue
    write_async(pipe_w, SYNC_SUCCESS, "").await?;

    if p.init {
        info!(logger, "notify child parent ready to run prestart hook!");
        read_async(pipe_r).await?;

        info!(logger, "get ready to run prestart hook!");

        // guest Prestart hook
        // * should be executed during the start operation, and before the container
        //   command is executed
        // * the executable file is in agent namespace
        // * should also be executed in agent namespace.
        if let Some(hooks) = spec.hooks().as_ref() {
            info!(logger, "guest Prestart hook");
            let mut hook_states = HookStates::new();
            hook_states.execute_hooks(
                hooks.prestart().clone().unwrap_or_default().as_slice(),
                Some(st.clone()),
            )?;
        }

        // notify child run prestart hooks completed
        info!(logger, "notify child run prestart hook completed!");
        write_async(pipe_w, SYNC_SUCCESS, "").await?;
    }

    info!(logger, "wait for child process ready to run exec");
    read_async(pipe_r).await?;

    Ok(())
}

fn write_mappings(logger: &Logger, path: &str, maps: &[LinuxIdMapping]) -> Result<()> {
    let data = maps
        .iter()
        .filter(|m| m.size() != 0)
        .map(|m| format!("{} {} {}\n", m.container_id(), m.host_id(), m.size()))
        .collect::<Vec<_>>()
        .join("");

    info!(logger, "mapping: {}", data);
    if !data.is_empty() {
        let fd = fcntl::open(path, OFlag::O_WRONLY, Mode::empty())?;
        defer!(unistd::close(fd).unwrap());
        unistd::write(fd, data.as_bytes())
            .inspect_err(|_| info!(logger, "cannot write mapping"))?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PidNs {
    pub(super) enabled: bool,
    pub(super) fd: Option<i32>,
}

impl PidNs {
    pub fn new(enabled: bool, fd: Option<i32>) -> Self {
        Self { enabled, fd }
    }
}
