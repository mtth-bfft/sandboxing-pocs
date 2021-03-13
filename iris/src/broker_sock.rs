use std::sync::Once;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use crate::LIBIRIS_SOCKET_FD_ENV_NAME;

// Unix socket shared between threads. UnixStream sockets are Sync, so access
// is thread-safe once initialized. Every access remains unsafe in the Rust sense
// of the term, and must be preceded by a call to LIBIRIS_SOCKET_FD_INIT to ensure
// the variable has been initialized.
static mut LIBIRIS_SOCKET_FD: Option<UnixStream> = None;
static LIBIRIS_SOCKET_FD_INIT: Once = Once::new();

pub fn libiris_get_broker_socket() -> Option<&'static UnixStream> {
    LIBIRIS_SOCKET_FD_INIT.call_once(|| {
        if let Ok(fd_num) = std::env::var(LIBIRIS_SOCKET_FD_ENV_NAME) {
            println!(" [.] Socket from broker found: {}", fd_num);
            if let Ok(n) = fd_num.parse::<i32>() {
                std::env::remove_var(LIBIRIS_SOCKET_FD_ENV_NAME);
                // Only this initialization closure (run once) will do this, so it is safe to
                // take ownership of this file descriptor.
                let sock = unsafe { UnixStream::from_raw_fd(n) };
                // During this closure's execution, other accesses to LIBIRIS_SOCKET_FD
                // through libiris_get_broker_socket() are blocked (and there must be no other
                // way to access it), so it is safe to write to it here.
                unsafe { LIBIRIS_SOCKET_FD = Some(sock); }
            }
        }
    });
    // At this point, LIBIRIS_SOCKET_FD may or may not be initialized (e.g. due to environment variable
    // fetching/parsing error), but it will never be written to again, so we can access it safely.
    unsafe { LIBIRIS_SOCKET_FD.as_ref() }
}

