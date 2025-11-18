//! # 容器镜像管理
//!
//! 提供容器镜像的拉取、解压和管理功能。

pub mod cdh;

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use safe_path::scoped_join;
use slog::Logger;

/// 镜像工作目录
///
/// 用于存储镜像层和解压后的内容。
pub const IMAGE_WORK_DIR: &str = "/tmp/runcell/image/";

/// 容器基础��录
///
/// 用于存储容器 bundle。
pub const CONTAINER_BASE: &str = "/tmp/runcell/containers/";

/// 拉取并解压镜像
///
/// 从镜像源拉取容器镜像,并解压到指定的 bundle 目录。
///
/// # 参数
/// - `image`: 镜像名称或路径
/// - `container_id`: 容器 ID
/// - `logger`: 日志记录器
///
/// # 返回
/// 返回 rootfs 路径
///
/// # 工作流程
/// 1. 验证容器 ID
/// 2. 创建 bundle 目录
/// 3. 拉取或加载镜像
/// 4. 解压镜像到 rootfs
/// 5. 返回 rootfs 路径
///
/// # 镜像格式
/// 支持以下格式:
/// - `file:///path/to/image.tar`: 本地 tar 镜像
/// - `dir:///path/to/bundle`: 本地 bundle 目录
/// - `docker://registry/image:tag`: Docker 镜像 (需要 CDH 支持)
/// - 其他: 视为本地路径
pub async fn pull_and_extract(image: &str, container_id: &str, logger: &Logger) -> Result<String> {
    info!(logger, "Pulling and extracting image"; "image" => image, "container_id" => container_id);

    // 验证容器 ID (基本检查)
    if container_id.is_empty() {
        bail!("Container ID cannot be empty");
    }

    if container_id.contains('/') || container_id.contains("..") {
        bail!("Container ID contains invalid characters");
    }

    // 创建 bundle 目录
    // 确保容器基础目录存在
    let container_base = Path::new(CONTAINER_BASE);
    if !container_base.exists() {
        fs::create_dir_all(container_base).with_context(|| {
            format!(
                "Failed to create container base directory: {}",
                CONTAINER_BASE
            )
        })?;
    }

    let bundle_path = scoped_join(CONTAINER_BASE, container_id).with_context(|| {
        format!(
            "Failed to create bundle path for container {}",
            container_id
        )
    })?;

    fs::create_dir_all(&bundle_path)
        .with_context(|| format!("Failed to create bundle directory: {:?}", bundle_path))?;

    // 根据镜像格式选择处理方式
    if image.starts_with("file://") {
        // 本地 tar 文件
        let tar_path = image.trim_start_matches("file://");
        extract_tar_image(tar_path, &bundle_path, logger).await?;
    } else if image.starts_with("dir://") {
        // 本地目录
        let dir_path = image.trim_start_matches("dir://");
        copy_local_bundle(dir_path, &bundle_path, logger).await?;
    } else if image.starts_with("docker://") || image.contains('/') {
        // Docker 镜像或远程镜像 - 需要 CDH 支持
        #[cfg(feature = "cdh")]
        {
            cdh::pull_image_via_cdh(image, &bundle_path, logger).await?;
        }
        #[cfg(not(feature = "cdh"))]
        {
            warn!(logger, "CDH support not enabled, treating as local path"; "image" => image);
            // 尝试作为本地路径处理
            if Path::new(image).exists() {
                copy_local_bundle(image, &bundle_path, logger).await?;
            } else {
                bail!("Image {} not found and CDH support is not enabled", image);
            }
        }
    } else {
        // 默认作为本地路径处理
        if Path::new(image).exists() {
            copy_local_bundle(image, &bundle_path, logger).await?;
        } else {
            bail!("Image path does not exist: {}", image);
        }
    }

    // 返回 rootfs 路径
    let rootfs_path = scoped_join(&bundle_path, "rootfs")
        .with_context(|| "Failed to create rootfs path".to_string())?;

    info!(logger, "Image extracted successfully"; "rootfs" => rootfs_path.display().to_string());

    Ok(rootfs_path.display().to_string())
}

/// 从 tar 文件提取镜像
///
/// # 参数
/// - `tar_path`: tar 文件路径
/// - `bundle_path`: bundle 目录
/// - `logger`: 日志记录器
async fn extract_tar_image(tar_path: &str, bundle_path: &Path, logger: &Logger) -> Result<()> {
    info!(logger, "Extracting tar image"; "tar" => tar_path, "bundle" => bundle_path.display().to_string());

    let tar_file = Path::new(tar_path);
    if !tar_file.exists() {
        bail!("Tar file does not exist: {}", tar_path);
    }

    // 创建 rootfs 目录
    let rootfs = scoped_join(bundle_path, "rootfs")?;
    fs::create_dir_all(&rootfs)
        .with_context(|| format!("Failed to create rootfs directory: {:?}", rootfs))?;

    // 使用 tar 命令解压
    let status = tokio::process::Command::new("tar")
        .arg("-xf")
        .arg(tar_path)
        .arg("-C")
        .arg(&rootfs)
        .status()
        .await
        .context("Failed to execute tar command")?;

    if !status.success() {
        bail!("Failed to extract tar file: {}", tar_path);
    }

    info!(logger, "Tar extraction completed"; "rootfs" => rootfs.display().to_string());

    Ok(())
}

/// 复制本地 bundle
///
/// # 参数
/// - `src_path`: 源 bundle 路径
/// - `dest_path`: 目标 bundle 路径
/// - `logger`: 日志记录器
async fn copy_local_bundle(src_path: &str, dest_path: &Path, logger: &Logger) -> Result<()> {
    info!(logger, "Copying local bundle"; "src" => src_path, "dest" => dest_path.display().to_string());

    let src = Path::new(src_path);
    if !src.exists() {
        bail!("Source bundle does not exist: {}", src_path);
    }

    // 如果源路径包含 rootfs 目录,直接复制
    let src_rootfs = src.join("rootfs");
    let dest_rootfs = dest_path.join("rootfs");

    if src_rootfs.exists() {
        // 复制整个 rootfs 目录
        copy_dir_recursive(&src_rootfs, &dest_rootfs)?;

        // 如果有 config.json,也复制过去
        let src_config = src.join("config.json");
        if src_config.exists() {
            let dest_config = dest_path.join("config.json");
            fs::copy(&src_config, &dest_config)
                .with_context(|| "Failed to copy config.json".to_string())?;
        }
    } else {
        // 源路径本身就是 rootfs,直接复制到 dest_path/rootfs
        fs::create_dir_all(&dest_rootfs)?;
        copy_dir_recursive(src, &dest_rootfs)?;
    }

    info!(logger, "Bundle copy completed");

    Ok(())
}

/// 递归复制目录
///
/// # 参数
/// - `src`: 源目录
/// - `dest`: 目标目录
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    if !dest.exists() {
        fs::create_dir_all(dest)
            .with_context(|| format!("Failed to create directory: {:?}", dest))?;
    }

    for entry in
        fs::read_dir(src).with_context(|| format!("Failed to read directory: {:?}", src))?
    {
        let entry = entry?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        // 获取元数据，但不跟随符号链接
        let metadata = fs::symlink_metadata(&src_path)?;

        if metadata.is_symlink() {
            // 处理符号链接
            let link_target = fs::read_link(&src_path)?;
            std::os::unix::fs::symlink(&link_target, &dest_path)
                .with_context(|| format!("Failed to create symlink: {:?}", dest_path))?;
        } else if metadata.is_dir() {
            // 递归复制目录
            copy_dir_recursive(&src_path, &dest_path)?;
        } else {
            // 复制普通文件
            fs::copy(&src_path, &dest_path)
                .with_context(|| format!("Failed to copy file: {:?}", src_path))?;
        }
    }

    Ok(())
}

/// 清理容器镜像
///
/// 删除容器的 bundle 目录。
///
/// # 参数
/// - `container_id`: 容器 ID
/// - `logger`: 日志记录器
pub fn cleanup_image(container_id: &str, logger: &Logger) -> Result<()> {
    info!(logger, "Cleaning up image"; "container_id" => container_id);

    let bundle_path = scoped_join(CONTAINER_BASE, container_id)?;

    if bundle_path.exists() {
        fs::remove_dir_all(&bundle_path)
            .with_context(|| format!("Failed to remove bundle directory: {:?}", bundle_path))?;

        info!(logger, "Image cleanup completed");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use slog::Drain;
    use tempfile::tempdir;

    use super::*;

    fn test_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[tokio::test]
    async fn test_copy_local_bundle() {
        let logger = test_logger();
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("src");
        let dest_dir = temp_dir.path().join("dest");

        // 创建测试 bundle
        let src_rootfs = src_dir.join("rootfs");
        fs::create_dir_all(&src_rootfs).unwrap();
        fs::write(src_rootfs.join("test.txt"), "test content").unwrap();

        // 复制 bundle
        copy_local_bundle(src_dir.to_str().unwrap(), &dest_dir, &logger)
            .await
            .unwrap();

        // 验证
        let dest_rootfs = dest_dir.join("rootfs");
        assert!(dest_rootfs.exists());
        assert!(dest_rootfs.join("test.txt").exists());
    }

    #[test]
    fn test_copy_dir_recursive() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("src");
        let dest_dir = temp_dir.path().join("dest");

        // 创建测试目录结构
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("file1.txt"), "content1").unwrap();

        let sub_dir = src_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::write(sub_dir.join("file2.txt"), "content2").unwrap();

        // 复制
        copy_dir_recursive(&src_dir, &dest_dir).unwrap();

        // 验证
        assert!(dest_dir.exists());
        assert!(dest_dir.join("file1.txt").exists());
        assert!(dest_dir.join("subdir").exists());
        assert!(dest_dir.join("subdir/file2.txt").exists());
    }
}
