use std::{
    any::Any,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, anyhow};
use cgroups::{
    BlkIoDeviceResource, BlkIoDeviceThrottleResource, Cgroup, CgroupPid, Controller,
    DeviceResource, HugePageResource, MaxValue, NetworkPriority,
    blkio::{BlkIoController, BlkIoData, IoService},
    cpu::CpuController,
    cpuacct::CpuAcctController,
    cpuset::CpuSetController,
    devices::{DevicePermissions, DeviceType},
    freezer::{FreezerController, FreezerState},
    hugetlb::HugeTlbController,
    memory::MemController,
    pid::PidController,
};
use libc::{self, pid_t};
use oci::{
    LinuxBlockIo, LinuxCpu, LinuxDevice, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxHugepageLimit, LinuxMemory, LinuxNetwork, LinuxPids, LinuxResources, Spec,
};
use oci_spec::runtime as oci;
use protobuf::MessageField;
use protocols::agent::{
    BlkioStats, BlkioStatsEntry, CgroupStats, CpuStats, CpuUsage, HugetlbStats, MemoryData,
    MemoryStats, PidsStats, ThrottlingData,
};
use serde::{Deserialize, Serialize};

use super::DevicesCgroupInfo;
use crate::{
    cgroups::{CgroupManager, rule_for_all_devices},
    container::DEFAULT_DEVICES,
};
