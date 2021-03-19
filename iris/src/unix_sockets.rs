use libc::{c_int, c_void};
use core::ptr::null_mut;
use std::io::Error;
use crate::LIBIRIS_IPC_MESSAGE_MAX_SIZE;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::prelude::RawFd;
use std::convert::TryInto;

// This entire file is just here to compensate for the fact that the current std::os::unix::net::UnixStream
// has no support for SOCK_SEQPACKET, and support for passing file descriptors as ancillary data is only
// available in nightly. This file will go away as soon as these will be fixed.

pub(crate) struct UnixSocket {
    file_descriptor: c_int,
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.file_descriptor); }
    }
}

impl AsRawFd for UnixSocket {
    fn as_raw_fd(&self) -> RawFd
    {
        self.file_descriptor
    }
}

impl FromRawFd for UnixSocket {
    unsafe fn from_raw_fd(fd: i32) -> Self {
        Self {
            file_descriptor: fd,
        }
    }
}

impl UnixSocket {       

    pub(crate) fn new(child_cloexec: bool) -> Result<(UnixSocket, UnixSocket), String>
    {
        let mut socks: Vec<c_int> = vec![-1, 2];
        let res = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, socks.as_mut_ptr()) };
        if res < 0 {
            return Err(format!("Could not create Unix socket pair: {}", Error::last_os_error()));
        }
        let (broker_socket, child_socket) = (socks[0], socks[1]);
        // Our end of the socket needs to be flagged CLOEXEC so it doesn't leak into any child
        let flags = unsafe { libc::fcntl(broker_socket, libc::F_GETFD, 0) };
        if flags == -1 {
            return Err(format!("fcntl(broker_socket, F_GETFD) failed with error {}", Error::last_os_error()));
        }
        let res = unsafe { libc::fcntl(broker_socket, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if res != 0 {
            return Err(format!("fcntl(broker_socket, F_SETFD, FD_CLOEXEC) failed with error {}", Error::last_os_error()));
        }
        // Set the child's end's CLOEXEC as requested
        let flags = unsafe { libc::fcntl(child_socket, libc::F_GETFD, 0) };
        if flags == -1 {
            return Err(format!("fcntl(child_socket, F_GETFD) failed with error {}", Error::last_os_error()));
        }
        let res = unsafe { libc::fcntl(child_socket, libc::F_SETFD, if child_cloexec { flags | libc::FD_CLOEXEC } else { flags & !(libc::FD_CLOEXEC) }) };
        if res != 0 {
            return Err(format!("fcntl(child_socket, F_SETFD, FD_CLOEXEC={}) failed with error {}", child_cloexec, Error::last_os_error()));
        }
        Ok((UnixSocket { file_descriptor: child_socket }, UnixSocket { file_descriptor: broker_socket }))
    }
    
    pub(crate) fn sendmsg_with_fd(&mut self, message: &[u8], file_descriptor: Option<i32>) -> Result<(), String>
    {
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;
        let mut cbuf = vec![0u8; cmsg_space];
        let msg_iovec = libc::iovec {
            iov_base: message.as_ptr() as *mut c_void, // mut is not used here, just required because iovec is used by recvmsg too
            iov_len: message.len(),
        };
        let msg = libc::msghdr {
            msg_name: null_mut(), // socket is already connected, no need for this
            msg_namelen: 0,
            msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec, // mut is not really used here either
            msg_iovlen: 1,
            msg_control: cbuf.as_mut_ptr() as *mut c_void,
            msg_controllen: cmsg_space * (if file_descriptor.is_some() { 1 } else { 0 }),
            msg_flags: 0, // unused
        };
        if let Some(file_descriptor) = file_descriptor {
            let cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg as *const _ as *mut libc::msghdr) };
            unsafe {
                (*cmsghdr).cmsg_level = libc::SOL_SOCKET;
                (*cmsghdr).cmsg_type = libc::SCM_RIGHTS;
                (*cmsghdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<c_int>() as u32) as usize;
                std::ptr::copy_nonoverlapping(&file_descriptor as *const c_int, libc::CMSG_DATA(cmsghdr) as *mut c_int, 1);
            }
        }
        let res = unsafe { libc::sendmsg(self.file_descriptor, &msg as *const libc::msghdr, libc::MSG_NOSIGNAL) };
        if res < 0 {
            return Err(format!("sendmsg() failed with error: {}", Error::last_os_error()));
        }
        Ok(())
    }

    pub(crate) fn recvmsg(&mut self) -> Result<Vec<u8>, String>
    {
        let mut buffer = vec![0u8; LIBIRIS_IPC_MESSAGE_MAX_SIZE];
        let msg_iovec = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };
        let mut msg = libc::msghdr {
            msg_name: null_mut(), // socket is already connected, no need for this
            msg_namelen: 0,
            msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec, // mut is not used here, just required by API
            msg_iovlen: 1,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0, // unused
        };
        let res = unsafe { libc::recvmsg(self.file_descriptor, &mut msg as *mut libc::msghdr, libc::MSG_NOSIGNAL | libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL) };
        if res < 0 {
            return Err(format!("recvmsg() failed with error: {}", Error::last_os_error()));
        }
        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            return Err("recvmsg() failed due to message too long".to_owned());
        }
        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err("recvmsg() failed due to message including an unexpected ancillary data".to_owned());
        }
        buffer.truncate(res.try_into().unwrap());
        Ok(buffer)
    }

    pub(crate) fn recvmsg_with_fd(&mut self) -> Result<(Vec<u8>, Option<c_int>), String>
    {
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;
        let mut cbuf = vec![0u8; cmsg_space];
        let mut buffer = vec![0u8; LIBIRIS_IPC_MESSAGE_MAX_SIZE];
        let msg_iovec = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };
        let mut msg = libc::msghdr {
            msg_name: null_mut(), // socket is already connected, no need for this
            msg_namelen: 0,
            msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec, // mut is not used here, just required by API
            msg_iovlen: 1,
            msg_control: cbuf.as_mut_ptr() as *mut c_void,
            msg_controllen: cmsg_space,
            msg_flags: 0, // unused
        };
        let res = unsafe { libc::recvmsg(self.file_descriptor, &mut msg as *mut libc::msghdr, libc::MSG_NOSIGNAL | libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL) };
        if res < 0 {
            return Err(format!("recvmsg() failed with error: {}", Error::last_os_error()));
        }
        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err("recvmsg() failed due to message including an unexpected ancillary data".to_owned());
        }
        let cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr) };
        let fd = unsafe { *(libc::CMSG_DATA(cmsghdr) as *const c_int) };
        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            unsafe { libc::close(fd) };
            return Err("recvmsg() failed due to message too long".to_owned());
        }
        buffer.truncate(res.try_into().unwrap());
        Ok((buffer, Some(fd)))
    }
}
