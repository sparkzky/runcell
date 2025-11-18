//! 容器管理命令实现

use std::{
    fs,
    path::Path,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use celler::{
    cgroups::DevicesCgroupInfo, container::LinuxContainer, process::Process, specconf::CreateOpts,
};
use oci_spec::runtime::Spec;
use slog::Logger;

use crate::ContainerCommands;

/// Bundle 基础目录
const BUNDLE_BASE: &str = "/tmp/runcell/bundles";

/// Container 状态目录  
const CONTAINER_STATE_BASE: &str = "/tmp/runcell/states";

/// 处理容器相关命令
pub async fn handle_container_command(cmd: ContainerCommands, logger: &Logger) -> Result<()> {
    match cmd {
        ContainerCommands::Create { id, rootfs, bundle } => {
            create_container(&id, &rootfs, bundle.as_deref(), logger).await?;
        }
        ContainerCommands::Run {
            id,
            image,
            command,
            args,
        } => {
            run_container(&id, &image, &command, &args, logger).await?;
        }
        ContainerCommands::Start { id } => {
            start_container(&id, logger).await?;
        }
        ContainerCommands::Delete { id } => {
            delete_container(&id, logger).await?;
        }
    }

    Ok(())
}

/// 创建容器
async fn create_container(
    id: &str,
    rootfs: &str,
    bundle: Option<&str>,
    logger: &Logger,
) -> Result<()> {
    slog::info!(logger, "创建容器"; "id" => id, "rootfs" => rootfs);

    // 确定 bundle 目录
    let bundle_path = bundle
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}/{}", BUNDLE_BASE, id));

    // 创建 bundle 目录
    fs::create_dir_all(&bundle_path)
        .with_context(|| format!("无法创建 bundle 目录: {}", bundle_path))?;

    // 生成最小化 OCI spec
    let spec = create_minimal_spec(rootfs, &["/bin/sh".to_string()])?;

    // 保存 config.json
    let config_path = format!("{}/config.json", bundle_path);
    spec.save(&config_path)
        .with_context(|| format!("无法保存 config.json 到 {}", config_path))?;

    slog::info!(logger, "容器配置已生成"; "config" => &config_path);

    Ok(())
}

/// 运行容器（创建+启动）
async fn run_container(
    id: &str,
    image: &str,
    command: &str,
    args: &[String],
    logger: &Logger,
) -> Result<()> {
    slog::info!(logger, "运行容器"; "id" => id, "image" => image, "command" => command);

    // 1. 拉取镜像
    slog::info!(logger, "正在拉取镜像...");
    let rootfs = storage::image::pull_and_extract(image, id, logger).await?;
    slog::info!(logger, "镜像拉取成功"; "rootfs" => &rootfs);

    // 2. 确定 bundle 目录
    let bundle_path = format!("{}/{}", BUNDLE_BASE, id);
    fs::create_dir_all(&bundle_path)?;

    // 3. 生成 OCI spec
    let mut cmd_args = vec![command.to_string()];
    cmd_args.extend(args.iter().cloned());

    let spec = create_minimal_spec(&rootfs, &cmd_args)?;

    // 4. 保存 config.json
    let config_path = format!("{}/config.json", bundle_path);
    spec.save(&config_path)?;

    slog::info!(logger, "OCI 配置已生成"; "config" => &config_path);

    // 5. 创建容器实例
    let create_opts = CreateOpts {
        cgroup_name: id.to_string(),
        use_systemd_cgroup: false,
        no_pivot_root: false,
        no_new_keyring: false,
        spec: Some(spec.clone()),
        rootless_euid: false,
        rootless_cgroup: false,
        container_name: id.to_string(),
    };

    let devcg_info = Some(Arc::new(RwLock::new(DevicesCgroupInfo::default())));

    slog::info!(logger, "正在创建容器实例...");

    let mut container =
        LinuxContainer::new(id, CONTAINER_STATE_BASE, devcg_info, create_opts, logger)?;

    slog::info!(logger, "容器创建成功！"; "id" => id);

    // 6. 创建并启动进程
    slog::info!(logger, "正在创建容器进程...");

    // 从 spec 中获取 process 配置
    let oci_process = spec
        .process()
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OCI spec 中缺少 process 配置"))?
        .clone();

    // 创建 Process 实例
    let process = Process::new(
        logger,
        &oci_process,
        id,   // exec_id
        true, // init process
        0,    // pipe_size (0 = default)
        None, // proc_io (None for simple case)
    )
    .context("创建 Process 失败")?;

    slog::info!(logger, "正在启动容器...");

    // 启动容器（包括 start + exec）
    container
        .run_container(process)
        .await
        .context("启动容器失败")?;

    slog::info!(logger, "容器启动成功！"; "id" => id);
    slog::info!(logger, "容器正在运行...");

    Ok(())
}

/// 启动已创建的容器
async fn start_container(id: &str, logger: &Logger) -> Result<()> {
    slog::info!(logger, "启动容器"; "id" => id);
    slog::warn!(logger, "start 命令暂未完全实现");

    Ok(())
}

/// 删除容器
async fn delete_container(id: &str, logger: &Logger) -> Result<()> {
    slog::info!(logger, "删除容器"; "id" => id);

    // 清理 bundle
    let bundle_path = format!("{}/{}", BUNDLE_BASE, id);
    if Path::new(&bundle_path).exists() {
        fs::remove_dir_all(&bundle_path)?;
        slog::info!(logger, "Bundle 已删除"; "path" => &bundle_path);
    }

    // 清理容器状态
    let state_path = format!("{}/{}", CONTAINER_STATE_BASE, id);
    if Path::new(&state_path).exists() {
        fs::remove_dir_all(&state_path)?;
        slog::info!(logger, "容器状态已删除"; "path" => &state_path);
    }

    // 清理镜像
    storage::image::cleanup_image(id, logger)?;

    slog::info!(logger, "容器删除完成"; "id" => id);

    Ok(())
}

/// 创建最小化的 OCI Spec
///
/// 这是一个简化版本，用于快速测试容器创建流程
fn create_minimal_spec(rootfs: &str, args: &[String]) -> Result<Spec> {
    // 从文件加载默认 spec 或创建一个基础的
    // 这里我们使用 oci_spec 的 builder 模式

    use oci_spec::runtime::{ProcessBuilder, RootBuilder, SpecBuilder};

    let process = ProcessBuilder::default().args(args.to_vec()).build()?;

    let root = RootBuilder::default().path(rootfs).build()?;

    let spec = SpecBuilder::default()
        .version("1.0.0")
        .process(process)
        .root(root)
        .build()?;

    Ok(spec)
}
