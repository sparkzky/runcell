# Runcell 使用文档

Runcell 是一个参照 rustjail 实现的轻量级容器运行时，支持容器的创建、运行和管理。

## 构建

```bash
cargo build
```

## 基础用法

### 容器管理命令

#### 运行容器

创建并启动一个容器：

```bash
sudo ./target/debug/runcell container run \
    --id <容器ID> \
    --image <镜像路径> \
    --command <执行命令> \
    --args <参数>
```

**示例：**

```bash
# 运行一个 sleep 进程的容器
sudo ./target/debug/runcell container run \
    --id test \
    --image /path/to/rootfs \
    --command /bin/sleep \
    --args 180
```

**参数说明：**
- `--id, -i`: 容器 ID（必需）
- `--image, -m`: 镜像源，目前只支持本地路径（必须是一个制作好的根文件系统，你可以用docker先拉取一个镜像然后导出为rootfs）
- `--command, -c`: 要执行的命令，默认 `/bin/sh`
- `--args, -a`: 命令参数

#### 删除容器

```bash
sudo ./target/debug/runcell container delete --id <容器ID>
```

**示例：**

```bash
sudo ./target/debug/runcell container delete --id test
```

#### 创建容器（仅创建，不启动）

```bash
sudo ./target/debug/runcell container create \
    --id <容器ID> \
    --rootfs <rootfs路径> \
    [--bundle <bundle目录>]
```

#### 启动容器

```bash
sudo ./target/debug/runcell container start --id <容器ID>
```

### 存储管理命令

#### 拉取镜像

```bash
sudo ./target/debug/runcell storage pull \
    --image <镜像源> \
    --container-id <容器ID> \
    [--cdh-socket <socket路径>]
```

#### 挂载

```bash
sudo ./target/debug/runcell storage mount \
    --source <源路径> \
    --target <目标路径> \
    --options <挂载选项>
```

#### 卸载

```bash
sudo ./target/debug/runcell storage umount --target <挂载点>
```

#### 清理镜像

```bash
sudo ./target/debug/runcell storage cleanup --container-id <容器ID>
```

## 调试技巧

### 查看容器进程

```bash
sudo ps aux | grep -E "sleep|runcell" | grep -v grep
```

### 进入容器执行命令

使用 `nsenter` 进入容器的命名空间：

```bash
# 先获取容器进程 PID
sudo ps aux | grep -E "sleep|runcell" | grep -v grep

# 使用 nsenter 进入容器执行命令
sudo nsenter -t <PID> -m -p -u -i -n <命令>
```

**示例：**

```bash
# 在容器中执行 ls /
sudo nsenter -t 126944 -m -p -u -i -n /bin/ls /
```

**nsenter 参数说明：**
- `-t <PID>`: 目标进程 PID
- `-m`: 进入 mount 命名空间
- `-p`: 进入 PID 命名空间
- `-u`: 进入 UTS 命名空间
- `-i`: 进入 IPC 命名空间
- `-n`: 进入 network 命名空间

## 完整示例

```bash
# 1. 构建项目
cargo build

# 2. 运行容器
sudo ./target/debug/runcell container run \
    --id test \
    --image /path/to/rootfs \
    --command /bin/sleep \
    --args 180

# 3. 查看容器进程
sudo ps aux | grep -E "sleep|runcell" | grep -v grep

# 4. 进入容器执行命令
sudo nsenter -t <PID> -m -p -u -i -n /bin/ls /

# 5. 删除容器
sudo ./target/debug/runcell container delete --id test
```

## 日志

使用 `-v` 或 `--verbose` 启用详细日志：

```bash
sudo ./target/debug/runcell -v container run --id test --image /path/to/rootfs
```

## 数据目录

- Bundle 目录: `/tmp/runcell/bundles/<容器ID>`
- 状态目录: `/tmp/runcell/states/<容器ID>`

## 依赖项

如果你要使用seccomp的话，确保本机有seccomp

sudo apt update
sudo apt install libseccomp-dev