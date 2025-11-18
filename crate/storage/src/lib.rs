//! # 容器存储和镜像管理模块
//!
//! 本模块提供容器运行时的存储抽象和镜像管理功能。
//!
//! ## 主要功能
//! - **存储设备抽象**: 统一的存储设备接口
//! - **存储处理器**: 支持多种存储类型（本地、块设备、镜像等）
//! - **镜像拉取**: 支持容器镜像拉取和解压
//! - **挂载管理**: 自动化挂载和卸载操作
//!
//! ## 支持的存储类型
//! - **Local**: 本地目录绑定挂载
//! - **Block**: 块设备挂载
//! - **Image**: 容器镜像拉取和挂载
//! - **Overlay**: OverlayFS 联合挂载
//!
//! ## 架构
//! ```text
//! ┌─────────────────────────────────┐
//! │   Storage Handler Manager       │
//! └─────────────┬───────────────────┘
//!               │
//!      ┌────────┴────────┬─────────────┬──────────────┐
//!      │                 │             │              │
//! ┌────▼────┐      ┌────▼────┐  ┌────▼────┐   ┌─────▼─────┐
//! │  Local  │      │  Block  │  │  Image  │   │  Overlay  │
//! │ Handler │      │ Handler │  │ Handler │   │  Handler  │
//! └─────────┘      └─────────┘  └─────────┘   └───────────┘
//! ```

#[macro_use]
extern crate slog;

pub mod device;
pub mod handler;
pub mod image;
pub mod mount;

use anyhow::{Result, anyhow};
pub use device::{StorageDevice, StorageDeviceGeneric};
pub use handler::{
    BlockHandler, ImagePullHandler, LocalHandler, OverlayHandler, STORAGE_HANDLERS, StorageContext,
    StorageHandler, StorageHandlerManager,
};
use slog::Logger;

/// 添加存储设备到容器
///
/// 处理一组存储配置，为每个存储创建相应的设备并挂载。
///
/// # 参数
/// - `logger`: 日志记录器
/// - `storages`: 存储配置列表
/// - `container_id`: 容器 ID
///
/// # 返回
/// 挂载点路径列表
///
/// # 工作流程
/// 1. 遍历所有存储配置
/// 2. 根据 driver 类型查找对应的 handler
/// 3. 调用 handler 创建存储设备
/// 4. 收集挂载点路径
pub async fn add_storages(
    logger: &Logger,
    storages: Vec<StorageConfig>,
    container_id: &str,
) -> Result<Vec<String>> {
    let mut mount_list = Vec::new();

    for storage in storages {
        let handler = STORAGE_HANDLERS
            .handler(&storage.driver)
            .ok_or_else(|| anyhow!("Unknown storage driver: {}", storage.driver))?;

        let logger = logger.new(o!(
            "subsystem" => "storage",
            "storage-type" => storage.driver.clone(),
            "container-id" => container_id.to_string(),
        ));

        let mut ctx = StorageContext {
            container_id: Some(container_id.to_string()),
            logger: &logger,
        };

        info!(logger, "Creating storage device"; "mount-point" => &storage.mount_point);

        match handler.create_device(storage.clone(), &mut ctx).await {
            Ok(device) => {
                if let Some(path) = device.path()
                    && !path.is_empty()
                {
                    mount_list.push(path.to_string());
                    info!(logger, "Storage device created successfully"; "path" => path);
                }
            }
            Err(e) => {
                error!(logger, "Failed to create storage device"; "error" => format!("{:?}", e));
                return Err(e);
            }
        }
    }

    Ok(mount_list)
}

/// 存储配置
///
/// 定义单个存储设备的配置信息。
#[derive(Debug, Clone, Default)]
pub struct StorageConfig {
    /// 存储驱动类型（local, block, image, overlay）
    pub driver: String,

    /// 驱动特定选项
    pub driver_options: Vec<String>,

    /// 源路径或设备
    pub source: String,

    /// 文件系统类型
    pub fstype: String,

    /// 挂载点
    pub mount_point: String,

    /// 挂载选项
    pub options: Vec<String>,
}

impl StorageConfig {
    /// 创建新的存储配置
    pub fn new(
        driver: impl Into<String>,
        source: impl Into<String>,
        mount_point: impl Into<String>,
    ) -> Self {
        Self {
            driver: driver.into(),
            source: source.into(),
            mount_point: mount_point.into(),
            ..Default::default()
        }
    }

    /// 设置文件系统类型
    pub fn with_fstype(mut self, fstype: impl Into<String>) -> Self {
        self.fstype = fstype.into();
        self
    }

    /// 设置挂载选项
    pub fn with_options(mut self, options: Vec<String>) -> Self {
        self.options = options;
        self
    }

    /// 设置驱动选项
    pub fn with_driver_options(mut self, driver_options: Vec<String>) -> Self {
        self.driver_options = driver_options;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_config() {
        let config = StorageConfig::new("local", "/host/path", "/container/path")
            .with_fstype("bind")
            .with_options(vec!["ro".to_string()]);

        assert_eq!(config.driver, "local");
        assert_eq!(config.source, "/host/path");
        assert_eq!(config.mount_point, "/container/path");
        assert_eq!(config.fstype, "bind");
        assert_eq!(config.options, vec!["ro"]);
    }
}
