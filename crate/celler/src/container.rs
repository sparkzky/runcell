use std::path::PathBuf;

use oci_spec::{runtime as oci, runtime::LinuxDevice};

use crate::specconf::CreateOpts;

pub type Config = CreateOpts;

lazy_static! {
    pub static ref DEFAULT_DEVICES: Vec<LinuxDevice> = {
        vec![
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/null"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(3)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/zero"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(5)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/full"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(7)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/tty"))
                .typ(oci::LinuxDeviceType::C)
                .major(5)
                .minor(0)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/urandom"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(9)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
            oci::LinuxDeviceBuilder::default()
                .path(PathBuf::from("/dev/random"))
                .typ(oci::LinuxDeviceType::C)
                .major(1)
                .minor(8)
                .file_mode(0o666_u32)
                .uid(0xffffffff_u32)
                .gid(0xffffffff_u32)
                .build()
                .unwrap(),
        ]
    };
}
