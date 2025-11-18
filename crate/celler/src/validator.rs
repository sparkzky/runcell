use std::{
    collections::HashMap,
    convert::TryFrom,
    path::{Component, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use lazy_static::lazy_static;
use oci::{Linux, LinuxIdMapping, LinuxNamespace, Spec};
use oci_spec::runtime as oci;
use regex::Regex;

/// OCI 容器规范验证器模块
///
/// 此模块负责验证 OCI 容器配置的合法性和安全性，包括：
/// - 系统控制参数（sysctl）验证
/// - 根文件系统路径验证
/// - 主机名和命名空间验证
/// - SELinux 安全标签验证
/// - 用户和 Cgroup 命名空间验证
/// - Rootless 容器特殊配置验证
use super::container::Config;

lazy_static! {
    /// 允许的 IPC 相关 sysctl 参数列表
    ///
    /// 这些参数用于控制进程间通信（IPC）资源限制，包括：
    /// - 消息队列相关：msgmax（单个消息最大大小）、msgmnb（队列最大字节数）、msgmni（队列最大数量）
    /// - 信号量相关：sem（信号量限制）
    /// - 共享内存相关：shmall（总共享内存页数）、shmmax（单段最大大小）、shmmni（最大段数）、shm_rmid_forced（强制删除）
    pub static ref SYSCTLS: HashMap<&'static str, bool> = {
        let mut m = HashMap::new();
        m.insert("kernel.msgmax", true);
        m.insert("kernel.msgmnb", true);
        m.insert("kernel.msgmni", true);
        m.insert("kernel.sem", true);
        m.insert("kernel.shmall", true);
        m.insert("kernel.shmmax", true);
        m.insert("kernel.shmmni", true);
        m.insert("kernel.shm_rmid_forced", true);
        m
    };
}

/// 验证 sysctl 系统参数配置的合法性
///
/// 检查规则：
/// 1. IPC 相关的 sysctl（如 kernel.msg*, kernel.shm*, fs.mqueue.*）需要 IPC
///    命名空间
/// 2. 网络相关的 sysctl（net.*）会被跳过，因为网络命名空间与宿主机共享
/// 3. UTS 命名空间相关：
///    - 允许 kernel.domainname
///    - 禁止 kernel.hostname（应通过 spec.hostname 设置）
/// 4. 其他未知的 sysctl 参数会被拒绝
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err` - 验证失败，包含错误信息
fn sysctl(oci: &Spec) -> Result<()> {
    let linux = get_linux(oci)?;

    let default_hash = HashMap::new();
    let sysctl_hash = linux.sysctl().as_ref().unwrap_or(&default_hash);
    let default_vec = vec![];
    let linux_namespaces = linux.namespaces().as_ref().unwrap_or(&default_vec);
    for (key, _) in sysctl_hash.iter() {
        // IPC 相关的 sysctl 需要 IPC 命名空间
        if SYSCTLS.contains_key(key.as_str()) || key.starts_with("fs.mqueue.") {
            if contain_namespace(linux_namespaces, "ipc") {
                continue;
            } else {
                return Err(anyhow!("Linux namespace does not contain ipc"));
            }
        }

        // 网络命名空间与宿主机共享，跳过网络相关的 sysctl
        if key.starts_with("net.") {
            continue;
        }

        // UTS 命名空间相关的配置
        if contain_namespace(linux_namespaces, "uts") {
            if key == "kernel.domainname" {
                continue;
            }

            if key == "kernel.hostname" {
                return Err(anyhow!("Kernel hostname specfied in Spec"));
            }
        }

        return Err(anyhow!("Sysctl config contains invalid settings"));
    }
    Ok(())
}

/// 从 OCI 规范中获取 Linux 特定配置
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(&Linux)` - Linux 配置引用
/// * `Err` - 规范中不包含 Linux 配置
fn get_linux(oci: &Spec) -> Result<&Linux> {
    oci.linux()
        .as_ref()
        .ok_or_else(|| anyhow!("Unable to get Linux section from Spec"))
}

/// 检查命名空间列表中是否包含指定类型的命名空间
///
/// # 参数
/// * `nses` - Linux 命名空间列表
/// * `key` - 命名空间类型的字符串表示（如 "ipc", "uts", "mnt", "user" 等）
///
/// # 返回
/// * `true` - 包含指定类型的命名空间
/// * `false` - 不包含或 key 无效
fn contain_namespace(nses: &[LinuxNamespace], key: &str) -> bool {
    let nstype = match oci::LinuxNamespaceType::try_from(key) {
        Ok(ns_type) => ns_type,
        Err(_e) => return false,
    };

    for ns in nses {
        if ns.typ() == nstype {
            return true;
        }
    }

    false
}

/// 验证根文件系统路径的安全性
///
/// 执行以下检查：
/// 1. 路径必须存在且是绝对路径
/// 2. 清理路径中的 `..` 和 `.` 等特殊组件
/// 3. 对比清理后的路径和规范化路径，防止符号链接攻击
///
/// # 安全性
/// 通过对比 cleaned 和 canonicalized 路径，可以检测：
/// - 符号链接攻击
/// - 路径遍历攻击
/// - 隐藏的目录跳转
///
/// # 参数
/// * `root` - 根文件系统路径字符串
///
/// # 返回
/// * `Ok(())` - 路径验证通过
/// * `Err` - 路径不合法或存在安全风险
fn rootfs(root: &str) -> Result<()> {
    let path = PathBuf::from(root);
    // 检查路径是否存在且为绝对路径
    if !path.exists() || !path.is_absolute() {
        return Err(anyhow!(
            "Path from {:?} does not exist or is not absolute",
            root
        ));
    }

    // 清理路径中的符号链接和 .. 等组件
    let mut stack: Vec<String> = Vec::new();
    for c in path.components() {
        if stack.is_empty() && (c == Component::RootDir || c == Component::ParentDir) {
            continue;
        }

        if c == Component::ParentDir {
            stack.pop();
            continue;
        }

        if let Some(v) = c.as_os_str().to_str() {
            stack.push(v.to_string());
        } else {
            return Err(anyhow!("Invalid path component (unable to convert to str)"));
        }
    }

    let mut cleaned = PathBuf::from("/");
    for e in stack.iter() {
        cleaned.push(e);
    }

    // 规范化路径（解析所有符号链接）
    let canon = path.canonicalize().context("failed to canonicalize path")?;
    if cleaned != canon {
        // 清理路径和规范化路径不一致，说明存在符号链接
        return Err(anyhow!(
            "There may be illegal symbols in the path name. Cleaned ({:?}) and canonicalized \
             ({:?}) paths do not match",
            cleaned,
            canon
        ));
    }

    Ok(())
}

/// 验证主机名配置的合法性
///
/// 如果规范中设置了 hostname，必须包含 UTS 命名空间。
/// UTS 命名空间允许容器拥有独立的主机名和域名。
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err` - 设置了 hostname 但缺少 UTS 命名空间
fn hostname(oci: &Spec) -> Result<()> {
    if oci.hostname().is_none() {
        return Ok(());
    }

    let linux = get_linux(oci)?;
    let default_vec = vec![];
    if !contain_namespace(linux.namespaces().as_ref().unwrap_or(&default_vec), "uts") {
        return Err(anyhow!("Linux namespace does not contain uts"));
    }

    Ok(())
}

/// 验证安全相关配置
///
/// 检查内容包括：
/// 1. SELinux 标签格式验证（进程标签和挂载标签）
/// 2. 如果配置了 masked_paths 或 readonly_paths，必须有 mount 命名空间
///
/// SELinux 标签格式：`user:role:type:level`
/// - user: SELinux 用户（如 system_u）
/// - role: SELinux 角色（如 system_r）
/// - type: SELinux 类型（如 container_t）
/// - level: 安全级别（如 s0, s0:c123,c456）
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err` - SELinux 标签格式错误或缺少必要的命名空间
fn security(oci: &Spec) -> Result<()> {
    let linux = get_linux(oci)?;
    // SELinux 标签格式：user:role:type:level
    let label_pattern = r".*_u:.*_r:.*_t:s[0-9]|1[0-5].*";
    let label_regex = Regex::new(label_pattern)?;

    let default_vec = vec![];
    // 验证进程的 SELinux 标签
    if let Some(process) = oci.process().as_ref()
        && process.selinux_label().is_some()
        && !label_regex.is_match(process.selinux_label().as_ref().unwrap())
    {
        return Err(anyhow!(
            "SELinux label for the process is invalid format: {:?}",
            &process.selinux_label()
        ));
    }

    // 验证挂载的 SELinux 标签
    if linux.mount_label().is_some() && !label_regex.is_match(linux.mount_label().as_ref().unwrap())
    {
        return Err(anyhow!(
            "SELinux label for the mount is invalid format: {}",
            linux.mount_label().as_ref().unwrap()
        ));
    }

    // 如果没有配置 masked_paths 和 readonly_paths，则无需进一步检查
    if linux.masked_paths().is_none() && linux.readonly_paths().is_none() {
        return Ok(());
    }

    // masked_paths 或 readonly_paths 需要 mount 命名空间支持
    if !contain_namespace(linux.namespaces().as_ref().unwrap_or(&default_vec), "mnt") {
        return Err(anyhow!("Linux namespace does not contain mount"));
    }

    Ok(())
}

/// 验证 ID 映射配置的有效性
///
/// 检查 UID/GID 映射中至少有一个映射的大小大于 0。
/// 这是为了防止创建无效的用户命名空间映射。
///
/// # 参数
/// * `maps` - Linux ID 映射列表（UID 或 GID 映射）
///
/// # 返回
/// * `Ok(())` - 至少存在一个有效的映射（size > 0）
/// * `Err` - 所有映射的 size 都为 0
fn idmapping(maps: &[LinuxIdMapping]) -> Result<()> {
    for map in maps {
        if map.size() > 0 {
            return Ok(());
        }
    }

    Err(anyhow!("No idmap has size > 0"))
}

/// 验证用户命名空间配置
///
/// 检查规则：
/// 1. 如果启用了用户命名空间：
///    - 检查系统是否支持用户命名空间（/proc/self/ns/user 是否存在）
///    - 验证 UID 和 GID 映射的有效性（至少有一个 size > 0 的映射）
/// 2. 如果没有用户命名空间：
///    - 不应该存在 UID 或 GID 映射配置
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err` - 配置不合法或系统不支持
fn usernamespace(oci: &Spec) -> Result<()> {
    let linux = get_linux(oci)?;

    let default_vec = vec![];
    if contain_namespace(linux.namespaces().as_ref().unwrap_or(&default_vec), "user") {
        // 检查系统是否支持用户命名空间
        let user_ns = PathBuf::from("/proc/self/ns/user");
        if !user_ns.exists() {
            return Err(anyhow!("user namespace not supported!"));
        }
        // 检查 ID 映射的有效性（至少有一个映射的 size > 0）
        let default_vec2 = vec![];
        idmapping(linux.uid_mappings().as_ref().unwrap_or(&default_vec2))
            .context("idmapping uid")?;
        idmapping(linux.gid_mappings().as_ref().unwrap_or(&default_vec2))
            .context("idmapping gid")?;
    } else {
        // 没有用户命名空间但存在 ID 映射配置
        if !linux.uid_mappings().is_none() || !linux.gid_mappings().is_none() {
            return Err(anyhow!("No user namespace, but uid or gid mapping exists"));
        }
    }

    Ok(())
}

/// 验证 Cgroup 命名空间配置
///
/// 如果规范中配置了 cgroup 命名空间，检查系统是否支持。
/// Cgroup 命名空间允许容器拥有独立的 cgroup 视图。
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err` - 配置了 cgroup 命名空间但系统不支持
fn cgroupnamespace(oci: &Spec) -> Result<()> {
    let linux = get_linux(oci)?;

    let default_vec = vec![];
    if contain_namespace(
        linux.namespaces().as_ref().unwrap_or(&default_vec),
        "cgroup",
    ) {
        let path = PathBuf::from("/proc/self/ns/cgroup");
        if !path.exists() {
            return Err(anyhow!("cgroup unsupported!"));
        }
    }
    Ok(())
}

/// 验证 rootless 容器的 ID 映射配置
///
/// Rootless 容器允许非 root 用户运行容器，必须满足：
/// 1. 必须配置用户命名空间
/// 2. 必须至少配置一个 UID 映射和一个 GID 映射
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err` - 缺少必要的配置
fn rootless_euid_mapping(oci: &Spec) -> Result<()> {
    let linux = get_linux(oci)?;

    let default_ns = vec![];
    if !contain_namespace(linux.namespaces().as_ref().unwrap_or(&default_ns), "user") {
        return Err(anyhow!("Linux namespace is missing user"));
    }

    if linux.uid_mappings().is_none() || linux.gid_mappings().is_none() {
        return Err(anyhow!(
            "Rootless containers require at least one UID/GID mapping"
        ));
    }

    Ok(())
}

/// 检查指定的 ID 是否在映射范围内
///
/// # 参数
/// * `maps` - ID 映射列表
/// * `id` - 要检查的容器内 ID
///
/// # 返回
/// * `true` - ID 在某个映射范围内
/// * `false` - ID 不在任何映射范围内
fn has_idmapping(maps: &[LinuxIdMapping], id: u32) -> bool {
    for map in maps {
        if id >= map.container_id() && id < map.container_id() + map.size() {
            return true;
        }
    }
    false
}

/// 验证 rootless 容器的挂载配置
///
/// 检查挂载选项中的 uid/gid 是否在 ID 映射范围内。
/// 这确保容器内的文件所有权能够正确映射到宿主机用户。
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 所有挂载的 uid/gid 都在映射范围内
/// * `Err` - 存在未映射的 uid/gid
fn rootless_euid_mount(oci: &Spec) -> Result<()> {
    let linux = get_linux(oci)?;

    let default_mounts = vec![];
    let oci_mounts = oci.mounts().as_ref().unwrap_or(&default_mounts);
    for mnt in oci_mounts.iter() {
        let default_options = vec![];
        let mnt_options = mnt.options().as_ref().unwrap_or(&default_options);
        for opt in mnt_options.iter() {
            // 检查 uid= 和 gid= 选项
            if opt.starts_with("uid=") || opt.starts_with("gid=") {
                let fields: Vec<&str> = opt.split('=').collect();

                if fields.len() != 2 {
                    return Err(anyhow!("Options has invalid field: {:?}", fields));
                }

                let id = fields[1]
                    .trim()
                    .parse::<u32>()
                    .context(format!("parse field {}", &fields[1]))?;

                if opt.starts_with("uid=")
                    && !has_idmapping(linux.uid_mappings().as_ref().unwrap_or(&vec![]), id)
                {
                    return Err(anyhow!("uid of {} does not have a valid mapping", id));
                }

                if opt.starts_with("gid=")
                    && !has_idmapping(linux.gid_mappings().as_ref().unwrap_or(&vec![]), id)
                {
                    return Err(anyhow!("gid of {} does not have a valid mapping", id));
                }
            }
        }
    }
    Ok(())
}

/// 验证 rootless 容器的完整配置
///
/// 组合验证 ID 映射和挂载配置。
///
/// # 参数
/// * `oci` - OCI 运行时规范
///
/// # 返回
/// * `Ok(())` - 验证通过
/// * `Err` - 验证失败
fn rootless_euid(oci: &Spec) -> Result<()> {
    rootless_euid_mapping(oci).context("rootless euid mapping")?;
    rootless_euid_mount(oci).context("rotless euid mount")?;
    Ok(())
}

/// OCI 容器配置的主验证函数
///
/// 这是容器运行时的入口验证函数，按顺序执行以下检查：
/// 1. 验证 Linux 配置存在
/// 2. 验证根文件系统路径（安全性检查）
/// 3. 验证主机名配置
/// 4. 验证安全配置（SELinux、masked paths 等）
/// 5. 验证用户命名空间和 ID 映射
/// 6. 验证 Cgroup 命名空间
/// 7. 验证 sysctl 参数
/// 8. 如果是 rootless 模式，额外验证 rootless 相关配置
///
/// # 参数
/// * `conf` - 容器配置，包含 OCI 规范和其他运行时配置
///
/// # 返回
/// * `Ok(())` - 所有验证通过，配置合法
/// * `Err` - 验证失败，包含具体的错误信息和上下文
///
/// # 示例
/// ```ignore
/// let config = Config { /* ... */ };
/// validate(&config)?;
/// ```
pub fn validate(conf: &Config) -> Result<()> {
    lazy_static::initialize(&SYSCTLS);
    let oci = conf
        .spec
        .as_ref()
        .ok_or_else(|| anyhow!("Invalid config spec"))?;

    if oci.linux().is_none() {
        return Err(anyhow!("oci Linux is none"));
    }

    let root = match oci.root().as_ref() {
        Some(v) => v.path().display().to_string(),
        None => return Err(anyhow!("oci root is none")),
    };

    // 执行各项验证
    rootfs(&root).context("rootfs")?;
    hostname(oci).context("hostname")?;
    security(oci).context("security")?;
    usernamespace(oci).context("usernamespace")?;
    cgroupnamespace(oci).context("cgroupnamespace")?;
    sysctl(oci).context("sysctl")?;

    // Rootless 模式的额外验证
    if conf.rootless_euid {
        rootless_euid(oci).context("rootless euid")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use oci::{LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, Process, Spec};
    use oci_spec::runtime as oci;

    use super::*;

    /// 测试 contain_namespace 函数的命名空间检测功能
    #[test]
    fn test_namespace() {
        let namespaces = [
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/sys/cgroups/net")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .path("/sys/cgroups/uts")
                .build()
                .unwrap(),
        ];

        // 应该能找到 net 和 uts 命名空间
        assert_eq!(contain_namespace(&namespaces, "net"), true);
        assert_eq!(contain_namespace(&namespaces, "uts"), true);

        // 空字符串、错误的大小写、不存在的命名空间应该返回 false
        assert_eq!(contain_namespace(&namespaces, ""), false);
        assert_eq!(contain_namespace(&namespaces, "Net"), false);
        assert_eq!(contain_namespace(&namespaces, "ipc"), false);
    }

    /// 测试 rootfs 路径验证功能
    ///
    /// 验证以下场景：
    /// - 不存在的路径应该失败
    /// - 相对路径应该失败
    /// - 包含符号链接的路径应该失败（/proc/self/root 是符号链接）
    /// - 正常的绝对路径应该成功
    /// - 包含 .. 的路径如果最终解析正确也应该成功
    #[test]
    fn test_rootfs() {
        // 这些路径应该失败
        rootfs("/_no_exit_fs_xxxxxxxxxxx").unwrap_err(); // 不存在
        rootfs("sys").unwrap_err(); // 相对路径
        rootfs("/proc/self/root").unwrap_err(); // 符号链接
        rootfs("/proc/self/root/sys").unwrap_err(); // 包含符号链接

        rootfs("/proc/self").unwrap_err(); // 符号链接
        rootfs("/./proc/self").unwrap_err(); // 包含符号链接
        rootfs("/proc/././self").unwrap_err(); // 包含符号链接
        rootfs("/proc/.././self").unwrap_err(); // 包含符号链接

        // 这些路径应该成功（/proc/uptime 是实际文件）
        rootfs("/proc/uptime").unwrap();
        rootfs("/../proc/uptime").unwrap(); // .. 在根目录被忽略
        rootfs("/../../proc/uptime").unwrap(); // 多个 .. 同样被忽略
        rootfs("/proc/../proc/uptime").unwrap(); // .. 被正确解析
        rootfs("/proc/../../proc/uptime").unwrap(); // 多级 .. 被正确解析
    }

    /// 测试 hostname 验证功能
    ///
    /// 验证以下场景：
    /// - 没有设置 hostname 应该通过
    /// - 设置 hostname 但没有 Linux 配置应该通过（会在 get_linux 中失败）
    /// - 设置 hostname 且有 UTS 命名空间应该通过
    #[test]
    fn test_hostname() {
        let mut spec = Spec::default();

        // 没有设置 hostname
        assert!(hostname(&spec).is_ok());

        // 设置了 hostname 但没有 Linux 配置
        spec.set_hostname(Some("a.test.com".to_owned()));
        assert!(hostname(&spec).is_ok());

        // 设置了 hostname 且有 UTS 命名空间
        let mut linux = Linux::default();
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/sys/cgroups/net")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .path("/sys/cgroups/uts")
                .build()
                .unwrap(),
        ];
        linux.set_namespaces(Some(namespaces));
        spec.set_linux(Some(linux));
        assert!(hostname(&spec).is_ok());
    }

    /// 测试安全配置验证功能
    ///
    /// 验证以下场景：
    /// 1. 基本的 Linux 配置应该通过
    /// 2. 配置 masked_paths 但没有 mount 命名空间应该失败
    /// 3. 配置 masked_paths 且有 mount 命名空间应该成功
    /// 4. 有效的 SELinux 标签格式应该通过
    /// 5. 无效的 SELinux 标签格式应该失败
    #[test]
    fn test_security() {
        let mut spec = Spec::default();

        // 基本的 Linux 配置
        let linux = Linux::default();
        spec.set_linux(Some(linux));
        security(&spec).unwrap();

        // 配置 masked_paths 但没有 mount 命名空间
        let mut linux = Linux::default();
        linux.set_masked_paths(Some(vec!["/test".to_owned()]));
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/sys/cgroups/net")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .path("/sys/cgroups/uts")
                .build()
                .unwrap(),
        ];
        linux.set_namespaces(Some(namespaces));
        spec.set_linux(Some(linux));
        security(&spec).unwrap_err(); // 应该失败

        // 配置 masked_paths 且有 mount 命名空间
        let mut linux = Linux::default();
        linux.set_masked_paths(Some(vec!["/test".to_owned()]));
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/sys/cgroups/net")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Mount)
                .path("/sys/cgroups/mount")
                .build()
                .unwrap(),
        ];
        linux.set_namespaces(Some(namespaces));
        spec.set_linux(Some(linux));
        assert!(security(&spec).is_ok());

        // SELinux 标签测试
        let valid_label = "system_u:system_r:container_t:s0:c123,c456";
        let mut process = Process::default();
        process.set_selinux_label(Some(valid_label.to_string()));
        spec.set_process(Some(process));
        security(&spec).unwrap(); // 有效标签应该通过

        let mut linux = Linux::default();
        linux.set_mount_label(Some(valid_label.to_string()));
        spec.set_linux(Some(linux));
        security(&spec).unwrap(); // 有效的挂载标签

        // 无效的 SELinux 标签格式（缺少 level 部分）
        let invalid_label = "system_u:system_r:container_t";
        let mut process = Process::default();
        process.set_selinux_label(Some(invalid_label.to_string()));
        spec.set_process(Some(process));
        security(&spec).unwrap_err(); // 应该失败

        let mut linux = Linux::default();
        linux.set_mount_label(Some(valid_label.to_string()));
        spec.set_linux(Some(linux));
        security(&spec).unwrap_err(); // 无效的进程标签导致失败
    }

    /// 测试用户命名空间验证功能
    ///
    /// 验证以下场景：
    /// 1. 没有 Linux 配置应该通过
    /// 2. 空的 Linux 配置应该通过
    /// 3. 有 UID 映射但 size 为 0 应该失败
    #[test]
    fn test_usernamespace() {
        let mut spec = Spec::default();
        assert!(usernamespace(&spec).is_ok());

        let linux = Linux::default();
        spec.set_linux(Some(linux));
        usernamespace(&spec).unwrap();

        // 创建 size 为 0 的 UID 映射
        let mut linux = Linux::default();

        let uidmap = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(1000u32)
            .size(0u32)
            .build()
            .unwrap();

        linux.set_uid_mappings(Some(vec![uidmap]));
        spec.set_linux(Some(linux));
        usernamespace(&spec).unwrap_err(); // size 为 0 应该失败
    }

    /// 测试 rootless 容器的验证功能
    ///
    /// 验证以下场景：
    /// 1. 没有 Linux 配置应该失败
    /// 2. 没有用户命名空间应该失败
    /// 3. 有用户命名空间但没有 ID 映射应该失败
    /// 4. 有完整的 ID 映射应该成功
    /// 5. 挂载选项中的 uid/gid 必须在映射范围内
    #[test]
    fn test_rootless_euid() {
        let mut spec = Spec::default();

        // 测试场景：没有 Linux 配置
        rootless_euid_mapping(&spec).unwrap_err();
        rootless_euid_mount(&spec).unwrap_err();

        // 测试场景：没有用户命名空间
        let linux = Linux::default();
        spec.set_linux(Some(linux));
        rootless_euid_mapping(&spec).unwrap_err();

        // 测试场景：依然没有用户命名空间
        let linux = spec.linux_mut().as_mut().unwrap();
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/sys/cgroups/net")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .path("/sys/cgroups/uts")
                .build()
                .unwrap(),
        ];
        linux.set_namespaces(Some(namespaces));
        rootless_euid_mapping(&spec).unwrap_err();

        // 测试场景：有用户命名空间，配置 UID/GID 映射
        let linux = spec.linux_mut().as_mut().unwrap();
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/sys/cgroups/net")
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::User)
                .path("/sys/cgroups/user")
                .build()
                .unwrap(),
        ];
        linux.set_namespaces(Some(namespaces));

        // 创建有效的 UID/GID 映射（容器内 0-999 映射到宿主机 1000-1999）
        let uidmap = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(1000u32)
            .size(1000u32)
            .build()
            .unwrap();
        let gidmap = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(1000u32)
            .size(1000u32)
            .build()
            .unwrap();

        linux.set_uid_mappings(Some(vec![uidmap]));
        linux.set_gid_mappings(Some(vec![gidmap]));
        rootless_euid_mapping(&spec).unwrap(); // 应该成功

        // 测试挂载选项：uid=10000 超出映射范围 (0-999)
        let mut oci_mount = oci::Mount::default();
        oci_mount.set_destination("/app".into());
        oci_mount.set_typ(Some("tmpfs".to_owned()));
        oci_mount.set_source(Some("".into()));
        oci_mount.set_options(Some(vec!["uid=10000".to_owned()]));
        spec.mounts_mut().as_mut().unwrap().push(oci_mount);
        rootless_euid_mount(&spec).unwrap_err(); // 应该失败

        // 测试挂载选项：uid=500, gid=500 在映射范围内
        let mut oci_mount = oci::Mount::default();
        oci_mount.set_destination("/app".into());
        oci_mount.set_typ(Some("tmpfs".to_owned()));
        oci_mount.set_source(Some("".into()));
        oci_mount.set_options(Some(vec!["uid=500".to_owned(), "gid=500".to_owned()]));
        spec.set_mounts(Some(vec![oci_mount]));

        rootless_euid(&spec).unwrap(); // 应该成功
    }

    /// 测试 sysctl 验证功能
    ///
    /// 验证以下场景：
    /// 1. kernel.domainname 需要 UTS 命名空间但没有时应该失败
    /// 2. 有 UTS 命名空间但配置了非 UTS 相关的 sysctl 应该失败
    #[test]
    fn test_sysctl() {
        let mut spec = Spec::default();

        let mut linux = Linux::default();
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path("/sys/cgroups/net")
                .build()
                .unwrap(),
        ];
        linux.set_namespaces(Some(namespaces));

        // 配置 kernel.domainname 但只有网络命名空间，缺少 UTS 命名空间
        let mut sysctl_hash = HashMap::new();
        sysctl_hash.insert("kernel.domainname".to_owned(), "test.com".to_owned());
        linux.set_sysctl(Some(sysctl_hash));

        spec.set_linux(Some(linux));
        sysctl(&spec).unwrap_err(); // 应该失败

        // 添加用户命名空间，但仍然缺少 UTS 命名空间
        spec.linux_mut()
            .as_mut()
            .unwrap()
            .namespaces_mut()
            .as_mut()
            .unwrap()
            .push(
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::User)
                    .path("/sys/cgroups/user")
                    .build()
                    .unwrap(),
            );
        assert!(sysctl(&spec).is_err()); // 依然失败
    }

    /// 测试完整的 validate 函数
    ///
    /// 验证以下场景：
    /// 1. 空配置应该失败
    /// 2. 只有 Linux 配置但没有 root 应该失败
    #[test]
    fn test_validate() {
        let spec = Spec::default();
        let mut config = Config {
            cgroup_name: "container1".to_owned(),
            use_systemd_cgroup: false,
            no_pivot_root: true,
            no_new_keyring: true,
            rootless_euid: false,
            rootless_cgroup: false,
            spec: Some(spec),
            container_name: "container1".to_owned(),
        };

        validate(&config).unwrap_err(); // 没有 Linux 配置应该失败

        let linux = Linux::default();
        config.spec.as_mut().unwrap().set_linux(Some(linux));
        validate(&config).unwrap_err(); // 没有 root 配置应该失败
    }
}
