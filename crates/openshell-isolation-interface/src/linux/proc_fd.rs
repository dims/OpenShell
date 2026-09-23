// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Strict `/proc/<tid>/fd` socket identity helpers.

#![allow(unsafe_code)]

use std::fs;
use std::io;
use std::os::fd::RawFd;

/// Snapshot socket inodes installed in process descriptor tables other than
/// `excluded_pid`.
///
/// Inaccessible or concurrently disappearing entries are
/// skipped. Callers use this only to reclaim bounded mediation metadata; a
/// later operation on an unregistered descriptor fails closed.
pub fn installed_socket_inodes_excluding(
    excluded_pid: u32,
) -> io::Result<std::collections::BTreeSet<u64>> {
    let mut inodes = std::collections::BTreeSet::new();
    for process in fs::read_dir("/proc")? {
        let Ok(process) = process else { continue };
        let Some(name) = process.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == excluded_pid {
            continue;
        }
        let Ok(descriptors) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let Some(digits) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
            else {
                continue;
            };
            if let Ok(inode) = digits.parse::<u64>() {
                inodes.insert(inode);
            }
        }
    }
    Ok(inodes)
}

/// Find the process holding the TCP socket bound to `local`.
///
/// For egress capture that has no calling thread to ask. A netfilter redirect
/// delivers a connection, not a notification, so the only handle on the opener
/// is its source address: `/proc/net/tcp` maps that to a socket inode, and a
/// scan of `/proc/<pid>/fd` maps the inode to a holder.
///
/// This is weaker than a notification TID and callers must treat it as such.
/// It is a snapshot taken after the fact: a workload that closes the socket
/// first cannot be named at all, and a socket shared across a fork resolves to
/// whichever holder is found first. Failure is reported, never guessed.
pub fn pid_owning_local_tcp(local: std::net::SocketAddrV4) -> io::Result<u32> {
    // /proc/net/tcp prints the address as the native u32 behind the big-endian
    // octets, and the port in big-endian: 127.0.0.1:8080 is "0100007F:1F90".
    let needle = format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(local.ip().octets()),
        local.port()
    );
    let table = fs::read_to_string("/proc/net/tcp")?;
    let inode = table
        .lines()
        .skip(1)
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let local_address = fields.nth(1)?;
            if local_address != needle {
                return None;
            }
            fields.nth(7)?.parse::<u64>().ok()
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no /proc/net/tcp entry for {local}"),
            )
        })?;

    for process in fs::read_dir("/proc")? {
        let Ok(process) = process else { continue };
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(descriptors) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            if target.to_str() == Some(&format!("socket:[{inode}]")) {
                return Ok(pid);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no process holds socket inode {inode}"),
    ))
}

/// Return the socket inode currently installed at `fd` in `tid`'s descriptor
/// table.
///
/// The result is only a snapshot. Callers must revalidate the seccomp
/// notification, task generation, and any retained socket cookie before a
/// state-changing operation.
pub fn socket_inode(tid: u32, fd: RawFd) -> io::Result<u64> {
    if tid == 0 || fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TID must be nonzero and FD must be nonnegative",
        ));
    }
    let target = fs::read_link(format!("/proc/{tid}/fd/{fd}"))?;
    let target = target.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "procfs descriptor target is not UTF-8",
        )
    })?;
    let digits = target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "procfs descriptor is not a socket",
            )
        })?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "procfs socket inode has an invalid representation",
        ));
    }
    digits.parse::<u64>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("procfs socket inode does not fit u64: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    #[test]
    fn identifies_socket_and_rejects_regular_file() {
        let mut pair = [-1; 2];
        // SAFETY: pair points to storage for exactly two returned descriptors.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        // SAFETY: successful socketpair returned two independently owned FDs.
        let left = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        // SAFETY: successful socketpair returned two independently owned FDs.
        let _right = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        assert!(socket_inode(std::process::id(), left.as_raw_fd()).unwrap() > 0);

        let file = File::open("/dev/null").expect("open regular descriptor");
        assert_eq!(
            socket_inode(std::process::id(), file.as_raw_fd())
                .expect_err("regular descriptor")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn installed_socket_snapshot_can_exclude_the_broker() {
        let mut pair = [-1; 2];
        // SAFETY: pair points to storage for exactly two returned descriptors.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        // SAFETY: successful socketpair returned two independently owned FDs.
        let left = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        // SAFETY: successful socketpair returned two independently owned FDs.
        let _right = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let inode = socket_inode(std::process::id(), left.as_raw_fd()).unwrap();

        assert!(
            installed_socket_inodes_excluding(u32::MAX)
                .unwrap()
                .contains(&inode)
        );
        assert!(
            !installed_socket_inodes_excluding(std::process::id())
                .unwrap()
                .contains(&inode)
        );
    }
}
