//! 存储和镜像命令实现

use std::{fs, path::Path};

use anyhow::{Context, Result};
use slog::Logger;

use crate::StorageCommands;

/// 处理存储相关命令
pub async fn handle_storage_command(cmd: StorageCommands, logger: &Logger) -> Result<()> {
    match cmd {
        StorageCommands::Mount {
            source,
            target,
            options,
        } => {
            slog::info!(logger, "执行绑定挂载"; "source" => &source, "target" => &target, "options" => format!("{:?}", options));

            // 确保源路径存在
            if !Path::new(&source).exists() {
                anyhow::bail!("源路径不存在: {}", source);
            }

            // 创建目录
            fs::create_dir_all(&target).with_context(|| format!("无法创建目标目录: {}", target))?;

            // 执行挂载
            storage::mount::bind_mount(&source, &target, &options)
                .with_context(|| format!("绑定挂载失败: {} -> {}", source, target))?;

            slog::info!(logger, "挂载成功"; "mount_point" => &target);

            // 验证挂载
            let is_mounted = storage::mount::is_mounted(&target)?;
            slog::info!(logger, "挂载状态验证"; "mounted" => is_mounted);

            Ok(())
        }

        StorageCommands::Umount { target } => {
            slog::info!(logger, "执行卸载"; "target" => &target);

            // 检查是否已挂载
            let is_mounted = storage::mount::is_mounted(&target)?;
            if !is_mounted {
                slog::warn!(logger, "目标未挂载"; "target" => &target);
                return Ok(());
            }

            // 执行卸载
            storage::mount::unmount(&target).with_context(|| format!("卸载失败: {}", target))?;

            slog::info!(logger, "卸载成功"; "target" => &target);

            Ok(())
        }

        StorageCommands::Pull {
            image,
            container_id,
        } => {
            slog::info!(logger, "拉取镜像"; "image" => &image, "container_id" => &container_id);

            // 调用镜像拉取功能
            let rootfs_path =
                storage::image::pull_and_extract(&image, &container_id, logger).await?;

            slog::info!(logger, "镜像拉取成功"; "rootfs" => &rootfs_path);

            // 验证 rootfs 是否存在
            if Path::new(&rootfs_path).exists() {
                slog::info!(logger, "Rootfs 路径验证成功"; "path" => &rootfs_path);

                // 列出 rootfs 内容
                if let Ok(entries) = fs::read_dir(&rootfs_path) {
                    let count = entries.count();
                    slog::info!(logger, "Rootfs 包含文件"; "count" => count);
                }
            } else {
                slog::error!(logger, "Rootfs 路径不存在"; "path" => &rootfs_path);
            }

            Ok(())
        }

        StorageCommands::Cleanup { container_id } => {
            slog::info!(logger, "清理镜像"; "container_id" => &container_id);

            storage::image::cleanup_image(&container_id, logger)?;

            slog::info!(logger, "清理完成"; "container_id" => &container_id);

            Ok(())
        }

        StorageCommands::Test { scenario } => {
            slog::info!(logger, "运行存储测试"; "scenario" => &scenario);

            match scenario.as_str() {
                "local" => test_local_mount(logger).await?,
                "tar" => test_tar_image(logger).await?,
                "dir" => test_dir_image(logger).await?,
                _ => anyhow::bail!("未知的测试场景: {}", scenario),
            }

            slog::info!(logger, "测试完成"; "scenario" => &scenario);

            Ok(())
        }
    }
}

/// 测试本地挂载功能
async fn test_local_mount(logger: &Logger) -> Result<()> {
    slog::info!(logger, "=== 测试本地绑定挂载 ===");

    // 创建测试目录
    let test_dir = "/tmp/runcell-test";
    let source = format!("{}/source", test_dir);
    let target = format!("{}/target", test_dir);

    // 清理旧数据
    let _ = fs::remove_dir_all(test_dir);

    // 创建源目录和测试文件
    fs::create_dir_all(&source)?;
    fs::write(format!("{}/test.txt", source), "Hello from runcell!")?;

    slog::info!(logger, "创建测试环境"; "source" => &source, "target" => &target);

    // 测试绑定挂载
    fs::create_dir_all(&target)?;
    storage::mount::bind_mount(&source, &target, &[])?;

    slog::info!(logger, "挂载成功，验证内容...");

    // 验证挂载内容
    let content = fs::read_to_string(format!("{}/test.txt", target))?;
    assert_eq!(content, "Hello from runcell!");

    slog::info!(logger, "内容验证成功"; "content" => &content);

    // 卸载
    storage::mount::unmount(&target)?;
    slog::info!(logger, "卸载成功");

    // 清理
    fs::remove_dir_all(test_dir)?;
    slog::info!(logger, "清理完成");

    Ok(())
}

/// 测试 tar 镜像拉取
async fn test_tar_image(logger: &Logger) -> Result<()> {
    slog::info!(logger, "=== 测试 tar 镜像拉取 ===");

    // 创建测试 tar 文件
    let test_dir = "/tmp/runcell-tar-test";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(test_dir)?;

    let rootfs_src = format!("{}/rootfs-src", test_dir);
    fs::create_dir_all(&rootfs_src)?;

    // 创建一些测试文件
    fs::write(format!("{}/hello.txt", rootfs_src), "Hello from tar!")?;
    fs::create_dir_all(format!("{}/bin", rootfs_src))?;
    fs::write(format!("{}/bin/sh", rootfs_src), "#!/bin/sh")?;

    slog::info!(logger, "创建测试 rootfs"; "path" => &rootfs_src);

    // 打包为 tar
    let tar_file = format!("{}/rootfs.tar", test_dir);
    let output = tokio::process::Command::new("tar")
        .arg("-cf")
        .arg(&tar_file)
        .arg("-C")
        .arg(&rootfs_src)
        .arg(".")
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("创建 tar 文件失败");
    }

    slog::info!(logger, "创建 tar 文件成功"; "path" => &tar_file);

    // 测试镜像拉取
    let container_id = "test-tar-container";
    let image_url = format!("file://{}", tar_file);

    let rootfs = storage::image::pull_and_extract(&image_url, container_id, logger).await?;

    slog::info!(logger, "镜像解压成功"; "rootfs" => &rootfs);

    // 验证内容
    let content = fs::read_to_string(format!("{}/hello.txt", rootfs))?;
    assert_eq!(content, "Hello from tar!");

    slog::info!(logger, "内容验证成功"; "content" => &content);

    // 清理
    storage::image::cleanup_image(container_id, logger)?;
    fs::remove_dir_all(test_dir)?;

    slog::info!(logger, "清理完成");

    Ok(())
}

/// 测试目录镜像
async fn test_dir_image(logger: &Logger) -> Result<()> {
    slog::info!(logger, "=== 测试目录镜像 ===");

    // 创建测试目录结构
    let test_dir = "/tmp/runcell-dir-test";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(test_dir)?;

    let bundle_src = format!("{}/bundle", test_dir);
    let rootfs_src = format!("{}/rootfs", bundle_src);
    fs::create_dir_all(&rootfs_src)?;

    // 创建测试文件
    fs::write(format!("{}/hello.txt", rootfs_src), "Hello from dir!")?;
    fs::create_dir_all(format!("{}/etc", rootfs_src))?;
    fs::write(format!("{}/etc/config", rootfs_src), "test-config")?;

    slog::info!(logger, "创建测试 bundle"; "path" => &bundle_src);

    // 测试镜像拉取
    let container_id = "test-dir-container";
    let image_url = format!("dir://{}", bundle_src);

    let rootfs = storage::image::pull_and_extract(&image_url, container_id, logger).await?;

    slog::info!(logger, "目录复制成功"; "rootfs" => &rootfs);

    // 验证内容
    let content = fs::read_to_string(format!("{}/hello.txt", rootfs))?;
    assert_eq!(content, "Hello from dir!");

    let config = fs::read_to_string(format!("{}/etc/config", rootfs))?;
    assert_eq!(config, "test-config");

    slog::info!(logger, "内容验证成功");

    // 清理
    storage::image::cleanup_image(container_id, logger)?;
    fs::remove_dir_all(test_dir)?;

    slog::info!(logger, "清理完成");

    Ok(())
}
