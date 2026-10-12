//! Raw layer-2 socket — the only module in the crate allowed to use `unsafe`.
//!
//! AF_PACKET/SOCK_RAW with ETH_P_ALL, bound to a single interface via
//! sockaddr_ll. In monitor mode delivered frames are radiotap + 802.11;
//! transmitted frames must already carry the radiotap INJECT_HDR prefix.

use std::ffi::CString;
use std::io;
use std::mem::size_of;

pub struct RawSocket {
    fd: i32,
    #[allow(dead_code)]
    ifindex: i32,
    ifname: String,
}

impl RawSocket {
    /// AF_PACKET SOCK_RAW ETH_P_ALL bound to ifname. Requires CAP_NET_RAW.
    pub fn open(ifname: &str) -> io::Result<Self> {
        let cname = CString::new(ifname)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ifname contains NUL"))?;
        // SAFETY: plain libc calls on stack-allocated data; fd/checks below.
        unsafe {
            let ifindex = libc::if_nametoindex(cname.as_ptr());
            if ifindex == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such interface: {ifname}"),
                ));
            }
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let sll = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: ifindex as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            if libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            ) < 0
            {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
            Ok(RawSocket {
                fd,
                ifindex: ifindex as i32,
                ifname: ifname.to_string(),
            })
        }
    }

    pub fn ifname(&self) -> String {
        self.ifname.clone()
    }

    /// Blocking receive of one L2 frame (radiotap + 802.11 in monitor mode).
    /// Retries transparently on EINTR.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: fd is a live socket owned by self; buf is valid for
            // buf.len() writable bytes.
            let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Transmit a frame prefixed with radiotap INJECT_HDR (len includes it).
    pub fn send(&self, frame_with_radiotap: &[u8]) -> io::Result<usize> {
        loop {
            // SAFETY: fd is a live socket; slice is valid readable memory.
            let n = unsafe {
                libc::send(
                    self.fd,
                    frame_with_radiotap.as_ptr().cast(),
                    frame_with_radiotap.len(),
                    0,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Receive timeout toggle for poll-style loops. 0 disables the timeout.
    pub fn set_timeout(&self, ms: u32) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: (ms / 1000) as libc::time_t,
            tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
        };
        // SAFETY: fd is a live socket; tv outlives the call.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        // SAFETY: fd came from socket() and is closed exactly once here.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without root/CAP_NET_RAW this returns EPERM; with it, loopback opens
    /// fine. Both outcomes are acceptable — the point is no panic and that a
    /// successful open reports its name.
    #[test]
    fn open_loopback_best_effort() {
        match RawSocket::open("lo") {
            Ok(sock) => {
                assert_eq!(sock.ifname(), "lo");
                assert!(sock.set_timeout(100).is_ok());
            }
            Err(e) => {
                let k = e.kind();
                assert!(matches!(
                    k,
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound | io::ErrorKind::Other
                ));
            }
        }
    }

    #[test]
    fn bogus_iface_is_an_error_not_a_panic() {
        let res = RawSocket::open("no_such_iface_zz");
        assert!(res.is_err());
    }
}
