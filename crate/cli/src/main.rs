//! # Runcell CLI
//!
//! 容器运行时命令行工具

use anyhow::Result;
use clap::{Parser, Subcommand};
use slog::{Drain, Logger, o};

mod container_cmd;
mod storage_cmd;

/// Runcell - 轻量级容器运行时
#[derive(Parser)]
#[command(name = "runcell")]
#[command(about = "容器运行时工具", long_about = None)]
struct Cli {
    /// 启用详细日志
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 存储和镜像管理命令
    #[command(subcommand)]
    Storage(StorageCommands),

    /// 容器管理命令
    #[command(subcommand)]
    Container(ContainerCommands),
}

#[derive(Subcommand, Debug)]
enum ContainerCommands {
    /// 创建容器
    Create {
        /// 容器 ID
        #[arg(short, long)]
        id: String,

        /// Rootfs 路径
        #[arg(short, long)]
        rootfs: String,

        /// Bundle 目录（可选，默认在 /tmp/runcell/bundles/{id}）
        #[arg(short, long)]
        bundle: Option<String>,
    },

    /// 运行容器（创建并启动）
    Run {
        /// 容器 ID
        #[arg(short, long)]
        id: String,

        /// 镜像源（支持 file://, dir://, 或本地路径）
        #[arg(short = 'm', long)]
        image: String,

        /// 要执行的命令
        #[arg(short, long, default_value = "/bin/sh")]
        command: String,

        /// 命令参数
        #[arg(short, long)]
        args: Vec<String>,
    },

    /// 启动已创建的容器
    Start {
        /// 容器 ID
        #[arg(short, long)]
        id: String,
    },

    /// 删除容器
    Delete {
        /// 容器 ID
        #[arg(short, long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum StorageCommands {
    /// 测试绑定挂载
    Mount {
        /// 源路径
        #[arg(short, long)]
        source: String,

        /// 目标挂载点
        #[arg(short, long)]
        target: String,

        /// 挂载选项 (ro, bind等)
        #[arg(short, long)]
        options: Vec<String>,
    },

    /// 测试卸载
    Umount {
        /// 挂载点路径
        #[arg(short, long)]
        target: String,
    },

    /// 测试镜像拉取
    Pull {
        /// 镜像源 (file://, dir://, 或本地路径)
        #[arg(short, long)]
        image: String,

        /// 容器 ID
        #[arg(short, long)]
        container_id: String,
    },

    /// 清理镜像
    Cleanup {
        /// 容器 ID
        #[arg(short, long)]
        container_id: String,
    },

    /// 测试完整存储流程
    Test {
        /// 测试场景 (local, tar, dir)
        #[arg(short, long, default_value = "local")]
        scenario: String,
    },
}

fn setup_logger(verbose: bool) -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let level = if verbose {
        slog::Level::Debug
    } else {
        slog::Level::Info
    };

    Logger::root(
        drain.filter_level(level).fuse(),
        o!("version" => env!("CARGO_PKG_VERSION")),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    // 检查是否是 init 子进程调用
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "init" {
        // 这是容器的 init 进程，直接调用 init_child
        celler::container::init_child();
        return Ok(());
    }

    let cli = Cli::parse();

    let logger = setup_logger(cli.verbose);
    let _guard = slog_scope::set_global_logger(logger.clone());

    slog::info!(logger, "Runcell starting"; "command" => format!("{:?}", cli.command));

    match cli.command {
        Commands::Storage(storage_cmd) => {
            storage_cmd::handle_storage_command(storage_cmd, &logger).await?;
        }
        Commands::Container(container_cmd) => {
            container_cmd::handle_container_command(container_cmd, &logger).await?;
        }
    }

    slog::info!(logger, "Command completed successfully");

    Ok(())
}
