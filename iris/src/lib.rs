use std::io::Error;
use std::thread;
use std::ffi::{CString, CStr};
use std::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};
use libc::{c_void, c_int};
use core::ptr::null;
use std::os::unix::net::UnixStream;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use seccomp_sys::{seccomp_init, seccomp_attr_set, seccomp_syscall_resolve_name, seccomp_rule_add, seccomp_load, seccomp_release, scmp_filter_attr, __NR_SCMP_ERROR, SCMP_ACT_ALLOW, SCMP_ACT_TRAP};
use serde::{Serialize, Deserialize};
use bincode::Options;

pub mod broker_sock;

use crate::broker_sock::libiris_get_broker_socket;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum IrisRequest {
    DontTrustMeAnymore,
    OpenFile { path: Vec<u8>, readonly: bool },
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum IrisResponse {
    YouAreNotTrustworthyAnymore,
    UnexpectedRequest,
    DeniedByPolicy,
}

// Name of the environment variable used to pass the socket file descriptor number
// from brokers to workers.
const LIBIRIS_SOCKET_FD_ENV_NAME: &str = "IRIS_SOCK_FD";

const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 12] = [
    "read",
    "write",
    "readv",
    "writev",
    "close",
    "sigaltstack",
    "munmap",
    "nanosleep",
    "exit_group",
    "restart_syscall",
    "rt_sigreturn",
    "rt_sigaction", // FIXME: should really be handled separately, to hook rt_sigaction(SIGSYS,..)
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
    // Stack on which the initial worker thread executes
    initial_thread_stack: Vec<u8>,
    // Handle to the thread which waits for the child process to exit
    manager_thread_handle: Option<std::thread::JoinHandle<Result<(), String>>>,
}

struct IrisWorkerParam {
    exe: String,
    argv: Vec<String>,
    envp: Vec<String>,
    request_socket: std::os::unix::net::UnixStream,
    execve_socket: std::os::unix::net::UnixStream,
}

impl Drop for IrisWorker {
    fn drop(&mut self) {
        if !self.has_exited() {
            panic!("IrisWorker dropped out of scope without proper error handling through wait_for_exit()");
        }
    }
}

impl IrisWorker {
    pub fn wait_for_exit(&mut self) -> Result<(), String> {
        if let Some(handle) = self.manager_thread_handle.take() {
            println!(" [.] Waiting for manager thread to exit");
            match handle.join() {
                Ok(Ok(())) => (),
                Ok(Err(e)) => return Err(format!("Manager thread exited with error: {}", e)),
                Err(e) => return Err(format!("Error while waiting for manager thread to exit: {:?}", e)),
            }
        }
        else {
            println!(" [.] Manager thread already exited");
        }
        Ok(())
    }
    pub fn has_exited(&self) -> bool {
        self.manager_thread_handle.is_none()
    }
}

extern "C" fn worker_entrypoint(arg: *mut c_void) -> c_int
{
    // Cast the argument back to the boxed IrisWorkerParam it was.
    // worker_entrypoint() must only be used by libiris_worker_new() so it is safe to take ownership here.
    let arg = unsafe { Box::from_raw(arg as *mut IrisWorkerParam) };
    println!(" [.] Worker {} started with PID={}", &arg.exe, unsafe { libc::getpid() });

    // TODO: move all this processing in libiris_worker_new(), where we can report the error correctly and instantly to the caller
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
    // This voluntarily leaks the socket file descriptor, so it is preserved across execve()
    let request_socket_fd = arg.request_socket.into_raw_fd();
    let request_socket_env_var = CString::new(format!("{}={}", LIBIRIS_SOCKET_FD_ENV_NAME, request_socket_fd)).unwrap();
    let envp: Vec<*const i8> = envp.iter().map(|x| x.as_ptr() as *const i8).chain(vec![request_socket_env_var.as_ptr(), null()]).collect();

    unsafe { libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };

    let execve_errno: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
    if let Err(e) = bincode_options.serialize_into(&arg.execve_socket, &execve_errno) {
        panic!("Failed to propagate execve() error to broker process: {}", e);
    }
    execve_errno as c_int
}

fn alloc_socketpair(child_cloexec: bool) -> Result<(UnixStream, UnixStream), String>
{
    let (child_socket, broker_socket) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(e) => return Err(format!("Could not create Unix socket pair: {}", e)),
    };
    // Our end of the socket will be flagged CLOEXEC by default, just ensure it really is
    let flags = unsafe { libc::fcntl(broker_socket.as_raw_fd(), libc::F_GETFD, 0) };
    if flags == -1 {
        return Err(format!("fcntl(broker_socket, F_GETFD) failed with error {}", Error::last_os_error()));
    }
    let res = unsafe { libc::fcntl(broker_socket.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if res != 0 {
        return Err(format!("fcntl(broker_socket, F_SETFD, FD_CLOEXEC) failed with error {}", Error::last_os_error()));
    }
    // Set the child's end as requested
    let flags = unsafe { libc::fcntl(child_socket.as_raw_fd(), libc::F_GETFD, 0) };
    if flags == -1 {
        return Err(format!("fcntl(child_socket, F_GETFD) failed with error {}", Error::last_os_error()));
    }
    let res = unsafe { libc::fcntl(child_socket.as_raw_fd(), libc::F_SETFD, if child_cloexec { flags | libc::FD_CLOEXEC } else { flags & !(libc::FD_CLOEXEC) }) };
    if res != 0 {
        return Err(format!("fcntl(child_socket, F_SETFD, FD_CLOEXEC={}) failed with error {}", child_cloexec, Error::last_os_error()));
    }
    Ok((child_socket, broker_socket))
}

pub fn libiris_worker_new(exe: &str, argv: &[&str], envp: &[&str]) -> Result<IrisWorker, String>
{
    if argv.len() < 1 {
        return Err("Invalid argument passed to libiris_worker_new(): empty argv".to_owned());
    }

    println!(" [.] Creating worker from PID={}", std::process::id());

    // Allocate a stack for the child to execute on
    let mut stack = vec![0; DEFAULT_WORKER_STACK_SIZE];
    let stack_ptr = stack.as_mut_ptr().wrapping_add(DEFAULT_WORKER_STACK_SIZE) as *mut c_void;

    // Allocate a socketpair for the child to send syscall requests to us
    let (child_request_socket, broker_request_socket) = alloc_socketpair(false)?;
    // Allocate a socketpair to detect any execve() error during worker startup, using CLOEXEC behaviour on these sockets
    let (child_execve_socket, broker_execve_socket) = alloc_socketpair(true)?;

    let worker_param = IrisWorkerParam {
        exe: exe.to_owned(),
        argv: argv.iter().map(|x| x.to_string()).collect(),
        envp: envp.iter().map(|x| x.to_string()).collect(),
        request_socket: child_request_socket,
        execve_socket: child_execve_socket,
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
    println!(" [.] Worker process created with PID={}", pid);

    // Free resources sent to the child process (e.g. close our child's part of socketpairs, which we
    // won't write to and would otherwise keep the socket opened even after our child dies)
    let worker_param = unsafe { Box::from_raw(worker_param) };
    std::mem::drop(worker_param);

    let bincode_options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(1*1024*1024);
    let execve_errcode: Option<i32> = match bincode_options.deserialize_from(&broker_execve_socket) {
        Ok(errno) => Some(errno),
        Err(e) => match *e {
            bincode::ErrorKind::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => None,
            _ => return Err(format!("Worker probably failed to execute, cannot deserialize message from execve socket: {:?}", e)),
        },
    };
    if let Some(errno) = execve_errcode {
        return Err(format!("execve() failed with error {}", errno));
    }

    // TODO: if CLONE_NEWNS failed and CAP_SYS_CHROOT is held, chroot to an empty directory
    // TODO: ensure sandboxed children don't have the (theoretical) right to ptrace() each others (if seccomp fails). Otherwise, prctl(undumpable) like chromium.

    let manager_thread_builder = thread::Builder::new().name(format!("iris_{}_manager", pid)).stack_size(32 * 1024);
    let manager_thread_handle = manager_thread_builder.spawn(move || -> Result<(), String> {
        let jobs: VecDeque<IrisRequest> = VecDeque::new();
        match bincode_options.deserialize_from(&broker_request_socket) {
            Ok(IrisRequest::DontTrustMeAnymore) => (),
            other => return Err(format!("Failed to receive initial request from worker: {:?} , did it exit before calling libiris_dont_trust_me_anymore() ?", other)),
        };
        if let Err(e) = bincode_options.serialize_into(&broker_request_socket, &IrisResponse::YouAreNotTrustworthyAnymore) {
            panic!("Failed to serialize response into socket: {:?}", e);
        }
        loop {
            let request: IrisRequest = match bincode_options.deserialize_from(&broker_request_socket) {
                Ok(request) => request,
                Err(e) => match *e {
                    bincode::ErrorKind::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    _ => panic!("Failed to deserialize request from socket: {:?}", e),
                },
            };
            println!(" [.] Received request: {:?}", request);
            let response = match request {
                IrisRequest::OpenFile { path, readonly } => {
                    panic!("Not implemented: {:?}", path);
                },
                _ => {
                    println!(" [!] Discarding unexpected request from worker: {:?}", request);
                    IrisResponse::UnexpectedRequest
                },
            };
            if let Err(e) = bincode_options.serialize_into(&broker_request_socket, &response) {
                panic!("Failed to serialize response into socket: {:?}", e);
            }
        }
        println!(" [.] Worker closed its side of the communication socket, waiting for it to die...");
        let mut status: c_int = 0;
        let res = unsafe { libc::waitpid(pid, &mut status as *mut c_int, libc::__WALL) };
        // Ignore ECHILD errors which can occur if the child exits right away before waitpid() starts
        if res != pid {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                println!(" [.] Process probably exited, waitpid() gave ECHILD in parent");
            }
            else {
                panic!("Manager thread failed to wait on PID={} (error {})", pid, std::io::Error::last_os_error());
            }
        }
        if libc::WIFEXITED(status) {
            println!(" [.] Worker reaped successfully, exited with code {}", libc::WEXITSTATUS(status));
        } else if libc::WIFSIGNALED(status) {
            println!(" [.] Worker reaped successfully, killed by signal {}", libc::WTERMSIG(status));
        } else {
            println!(" [.] Worker reaped successfully, unknown exit reason (status {})", status);
        }
        Ok(())
    });
    
    let manager_thread_handle = match manager_thread_handle {
        Ok(handle) => handle,
        Err(e) => return Err(format!("Unable to spawn thread to manage the worker's lifetime: {}", e)),
    };
    
    Ok(IrisWorker {
        pid: pid as u64,
        initial_thread_stack: stack,
        manager_thread_handle: Some(manager_thread_handle),
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

thread_local!(static SIGSYS_HANDLER_ALREADY_RUNNING: AtomicBool = AtomicBool::new(false));

extern "C" fn sigsys_handler(signal_no: c_int, siginfo: *const libc::siginfo_t, ucontext: *const c_void)
{
    if signal_no != libc::SIGSYS {
        return;
    }
    let siginfo = unsafe { *siginfo };
    if siginfo.si_code != 1 { // SYS_SECCOMP
        return;
    }
    
    let ucontext = ucontext as *mut libc::ucontext_t;
    let syscall_nr = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] };

    // sigaction() was passed SA_NODEFER so that SIGSYS is not masked when this
    // handler is called to handle a first SIGSYS. The only way a thread-directed
    // SIGSYS is received while this handler is running is if the handler tries to
    // perform a non-systematically approved syscall, which is a permanent failure
    // we want to catch early. Detect reentrancy using SIGSYS_HANDLER_ALREADY_RUNNING
    // and panic if it happens.
    SIGSYS_HANDLER_ALREADY_RUNNING.with(|b| {
        if b.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst) != Ok(false) {
            panic!("Syscall handler tried to use syscall {} which is not automatically approved, please consider opening an issue", syscall_nr);
        }
    });

    // /!\ Memory / print are unsafe in syscall handler, just for debugging purposes here
    let msg = format!(" [.] Syscall nr={} tried, needs broker proxying\n", syscall_nr);
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };

    let sock = libiris_get_broker_socket().unwrap();

    match syscall_nr {
        libc::SYS_openat => {
            let path = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RSI as usize] };
            let path = unsafe { CStr::from_ptr(path as *const libc::c_char) }.to_owned();
            println!(" [+] Requested access to file path {:?}", path);
            let request = IrisRequest::OpenFile {
                path: path.to_bytes().to_owned(),
                readonly: true,
            };
            let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
            if let Err(e) = bincode_options.serialize_into(sock, &request) {
                panic!("Failed to serialize file open request into socket: {:?}", e);
            }
            unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] = 2; }
        }
        _ => {
            unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] = -(libc::EPERM as i64); }
        }
    }
    SIGSYS_HANDLER_ALREADY_RUNNING.with(|b| {
        b.store(false, Ordering::SeqCst);
    });
}

pub fn libiris_dont_trust_me_anymore() -> Result<(), String>
{
    let sock = match libiris_get_broker_socket() {
        Some(s) => s,
        None => return Err("Could not find broker communication socket in environment variables, is this really a sandboxed process?".to_owned()),
    };
    let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
    if let Err(e) = bincode_options.serialize_into(sock, &IrisRequest::DontTrustMeAnymore) {
        panic!("Failed to serialize initial message to broker into socket: {}", e);
    }

    match bincode_options.deserialize_from(sock) {
        Ok(IrisResponse::YouAreNotTrustworthyAnymore) => (),
        other => panic!("Failed to deserialize initial response from broker socket: {:?}", other),
    };

    let mut empty_signal_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut empty_signal_set as *mut _) };
    let new_sigaction = libc::sigaction {
        sa_sigaction: sigsys_handler as usize,
        sa_mask: empty_signal_set,
        sa_flags: libc::SA_SIGINFO | libc::SA_NODEFER,
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
        println!(" [.] Allowing syscall {} / {}", syscall_name, syscall_nr);
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

