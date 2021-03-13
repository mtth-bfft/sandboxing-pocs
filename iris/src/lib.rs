use std::io::Error;
use std::thread;
use std::ffi::CString;
use libc::{c_void, c_int};
use core::ptr::null;
use std::os::unix::net::UnixStream;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use seccomp_sys::{seccomp_init, seccomp_attr_set, seccomp_syscall_resolve_name, seccomp_rule_add, seccomp_load, seccomp_release, scmp_filter_attr, __NR_SCMP_ERROR, SCMP_ACT_ALLOW, SCMP_ACT_TRAP};

pub mod broker_sock;

use crate::broker_sock::libiris_get_broker_socket;

// Name of the environment variable used to pass the socket file descriptor number
// from brokers to workers.
const LIBIRIS_SOCKET_FD_ENV_NAME: &str = "IRIS_SOCK_FD";

const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 8] = [
    "read",
    "write",
    "readv",
    "writev",
    "close",
    "sigaltstack",
    "munmap",
    "exit_group",
];
const DEFAULT_WORKER_STACK_SIZE: usize = 1 * 1024 * 1024;

// Global list of workers running under our process' control
// A reaper thread is created when the first item of this list is inserted,
// allowing one thread to wait() for any worker to terminate.
// The reaper thread terminates when the last worker is popped from this list
// const GLOBAL_WORKER_LIST = Mutex<Vec<IrisWorker>>;

pub struct IrisWorker {
    // ID of the worker process
    pid: u64,
    // Handle to the thread which waits for the child process to exit
    reaper_handle: Option<std::thread::JoinHandle<()>>,
}

struct IrisWorkerParam {
    exe: String,
    argv: Vec<String>,
    envp: Vec<String>,
    socket_fd: std::os::unix::net::UnixStream,
}

impl Drop for IrisWorker {
    fn drop(&mut self) {
        println!(" [.] Worker object dropped");
        self.wait_for_exit();
    }
}

impl IrisWorker {
    pub fn wait_for_exit(&mut self) -> Result<(), String> {
        if let Some(handle) = self.reaper_handle.take() {
            if let Err(e) = handle.join() {
                return Err(format!(" [!] Worker's reaper thread exited with error: {:?}", e));
            }
        }
        Ok(())
    }
    pub fn has_exited(&self) -> bool {
        self.reaper_handle.is_none()
    }
}

extern "C" fn worker_entrypoint(arg: *mut c_void) -> c_int
{
    // Cast the argument back to the boxed IrisWorkerParam it was.
    // worker_entrypoint() must only be used by libiris_worker_new() which ensures this is indeed a &IrisWorkerParam.
    let arg = unsafe { Box::from_raw(arg as *mut IrisWorkerParam) };
    println!(" [.] Worker {} started with PID={}", &arg.exe, unsafe { libc::getpid() });

    let exe = match CString::new(arg.exe.to_owned()) {
        Ok(s) => s,
        _ => {
            println!(" [!] Invalid worker commandline");
            return 1;
        },
    };
    let mut argv = Vec::new();
    for s in &arg.argv {
        match CString::new(s.to_owned()) {
            Ok(s) => argv.push(s),
            _ => {
                println!(" [!] Invalid worker argument \"{}\"", s);
                return 1;
            },
        };
    }
    let argv: Vec<*const i8> = argv.iter().map(|x| x.as_bytes_with_nul().as_ptr() as *const i8).chain(vec![null()]).collect();
    let mut envp = Vec::new();
    for s in &arg.envp {
        match CString::new(s.to_owned()) {
            Ok(s) => envp.push(s),
            _ => {
                println!(" [!] Invalid worker environment variable \"{}\"", s);
                return 1;
            },
        };
    }
    // Voluntarily leak the socket file descriptor, so it is preserved across execve()
    let socket_fd = arg.socket_fd.into_raw_fd();
    let socket_env_var = CString::new(format!("{}={}", LIBIRIS_SOCKET_FD_ENV_NAME, socket_fd)).unwrap();
    let envp: Vec<*const i8> = envp.iter().map(|x| x.as_ptr() as *const i8).chain(vec![socket_env_var.as_ptr(), null()]).collect();

    unsafe { libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    println!(" [!] Worker execve() failed: {}", Error::last_os_error());
    0
}

pub fn libiris_worker_new(exe: &str, argv: &[&str], envp: &[&str]) -> Result<IrisWorker, String>
{
    if argv.len() < 1 {
        return Err("Invalid argument passed to libiris_worker_new(): empty argv".to_owned());
    }

    println!(" [.] Creating worker");

    // Allocate a stack for the child to execute on
    let mut stack = vec![0; DEFAULT_WORKER_STACK_SIZE];
    let stack_ptr = stack.as_mut_ptr().wrapping_add(DEFAULT_WORKER_STACK_SIZE) as *mut c_void;

    // Allocate a socketpair for the child to send syscall requests to us
    let (child_socket, broker_socket) = match UnixStream::pair() {
        Ok((s1, s2)) => (s1, s2),
        Err(e) => return Err(format!("Could not create Unix socket pair: {}", e)),
    };
    // Mark our end of the socket as CLOEXEC right away so it doesn't leak to our children
    let res = unsafe { libc::fcntl(broker_socket.as_raw_fd(), libc::F_SETFD, libc::O_CLOEXEC) };
    if res != 0 {
        return Err(format!("fcntl(broker_socket, F_SETFD, O_CLOEXEC) failed with error {}", Error::last_os_error()));
    }

    let worker_param = IrisWorkerParam {
        exe: exe.to_owned(),
        argv: argv.iter().map(|x| x.to_string()).collect(),
        envp: envp.iter().map(|x| x.to_string()).collect(),
        socket_fd: child_socket,
    };

    // Unshare as many namespaces as possible
    // (this might not be possible due to insufficient privilege level,
    // and/or kernel support for (unprivileged) user namespaces.
    let clone_args = 0; //libc::CLONE_NEWUSER | libc::CLONE_NEWCGROUP | libc::CLONE_NEWIPC | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWUTS;

    let worker_param = Box::leak(Box::new(worker_param));
    let pid = unsafe {
        libc::clone(worker_entrypoint, stack_ptr, clone_args, worker_param as *const _ as *mut c_void)
    };
    if pid <= 0
    {
        println!(" [!] Could not create user namespace (not supported by kernel, or not privileged enough)");
        return Err(format!("clone() failed: {}", Error::last_os_error()));
    }
    println!(" [.] Worker created with PID={}", pid);

    // Close our child's part of the socketpair, which we won't use and would otherwise keep the socket opened even after our child dies
    let worker_param = unsafe { Box::from_raw(worker_param) };
    std::mem::drop(worker_param);

    // TODO: if CLONE_NEWNS failed and CAP_SYS_CHROOT is held, chroot to an empty directory
    // TODO: ensure sandboxed children don't have the (theoretical) right to ptrace() each others (if seccomp fails). Otherwise, prctl(undumpable) like chromium.
    // TODO: rlimit for number of file descriptors?

    let reaper_handle = thread::spawn(move || {
        let mut status: c_int = 0;
        let res = unsafe { libc::waitpid(pid, &mut status as *mut c_int, libc::__WALL) };
        // Ignore ECHILD errors which can occur if the child exits right away before waitpid() starts
        if res != pid {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                println!(" [.] Process probably exited, waitpid() gave ECHILD in parent");
            }
            else {
                println!(" [!] Reaper thread failed to wait on PID={} (error {})", pid, std::io::Error::last_os_error());
                return; // leak the child process memory and reaper thread on purpose, better than a crash
            }
        }
        std::mem::drop(stack);
        println!(" [.] Worker reaped successfully");
    });
    
    Ok(IrisWorker {
        pid: pid as u64,
        reaper_handle: Some(reaper_handle),
    })
}

fn get_syscall_number(name: &str) -> Result<i32, String>
{
    let name_null_terminated = CString::new(name).unwrap();
    let nr = unsafe { seccomp_syscall_resolve_name(name_null_terminated.as_ptr()) };
    if nr == __NR_SCMP_ERROR {
        return Err(format!("Syscall name \"{}\" not resolved by libseccomp", name));
    }
    Ok(nr)
}

extern "C" fn sigsys_handler(signal_no: c_int, siginfo: *const libc::siginfo_t, ucontext: *const c_void)
{
    if signal_no != libc::SIGSYS {
        return;
    }
    let siginfo = unsafe { *siginfo };
    if siginfo.si_code != 1 { // SYS_SECCOMP
        return;
    }
    let ucontext = unsafe { *(ucontext as *const libc::ucontext_t) };
    // /!\ Unsafe in syscall handler
    let msg = format!(" [.] Syscall handler called: rax={} ", ucontext.uc_mcontext.gregs[libc::REG_RAX as usize]);
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };

    //if ucontext.uc_mcontext.gregs[libc::REG_RAX as usize] == libc::SYS_open {
        
    //}

    let sock = libiris_get_broker_socket().unwrap();
}


pub fn libiris_dont_trust_me_anymore() -> Result<(), String>
{
    let sock = match libiris_get_broker_socket() {
        Some(s) => s,
        None => return Err("Could not find broker communication socket in environment variables, is this really a sandboxed process?".to_owned()),
    };

    let mut empty_signal_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut empty_signal_set as *mut _) };
    let new_sigaction = libc::sigaction {
        sa_sigaction: sigsys_handler as usize,
        sa_mask: empty_signal_set,
        sa_flags: libc::SA_SIGINFO,
        sa_restorer: None,
    };
    let mut old_sigaction: libc::sigaction = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::sigaction(libc::SIGSYS, &new_sigaction as *const _, &mut old_sigaction as *mut _) };
    if res != 0 {
        println!(" [!] sigaction(SIGSYS) failed with error {}", std::io::Error::last_os_error());
    }
    if old_sigaction.sa_sigaction != libc::SIG_DFL && old_sigaction.sa_sigaction != libc::SIG_IGN {
        println!(" [!] SIGSYS handler overwritten, the worker process might fail unexpectedly");
    }

    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        println!(" [!] prctl(PR_SET_NO_NEW_PRIVS) failed with error {}", std::io::Error::last_os_error());
    }

    let filter = unsafe { seccomp_init(SCMP_ACT_TRAP) }; //SCMP_ACT_ERRNO(libc::EPERM as u32)) };
    if filter.is_null() {
        println!(" [!] seccomp_init() failed, no error information available");
    }

    let res = unsafe { seccomp_attr_set(filter, scmp_filter_attr::SCMP_FLTATR_CTL_TSYNC, 1) };
    if res != 0 {
        println!(" [!] seccomp_attr_set(SCMP_FLTATR_CTL_TSYNC) failed with error {}", -res);
    }

    for syscall_name in &SYSCALLS_ALLOWED_BY_DEFAULT {
        let syscall_nr = get_syscall_number(&syscall_name).unwrap();
        let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 0) };
        if res != 0 {
            println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, {}) failed with code {}", syscall_name, -res);
        }
    }

    let res = unsafe { seccomp_load(filter) };
    if res != 0 {
        println!(" [!] seccomp_load() failed with error {}", -res);
    }

    unsafe { seccomp_release(filter) };

    println!(" [.] Worker ready to handle untrusted data");
    Ok(())
}

