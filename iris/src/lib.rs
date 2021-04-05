use std::io::Error;
use std::thread;
use std::ffi::{CString, CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::collections::VecDeque;
use libc::{c_void, c_int};
use core::ptr::null;
use seccomp_sys::{seccomp_init, seccomp_attr_set, seccomp_syscall_resolve_name, seccomp_rule_add, seccomp_load, seccomp_release, scmp_filter_attr, __NR_SCMP_ERROR, SCMP_ACT_ALLOW, SCMP_ACT_TRAP, scmp_arg_cmp, scmp_compare};
use serde::{Serialize, Deserialize};
use bincode::Options;
use std::os::unix::io::AsRawFd;
use std::convert::TryInto;

pub use iris_policy::IrisPolicy;

pub mod broker_sock;
mod unix_sockets;

use crate::broker_sock::libiris_get_broker_socket;
use crate::unix_sockets::UnixSocket;

#[derive(Serialize, Deserialize, PartialEq)]
enum IrisRequest {
    DontTrustMeAnymore,
    // path must be a non-null terminated OS string (not necessarily UTF-8 valid)
    OpenFile {
        path: Vec<u8>,
        read: bool,
        write: bool,
        create: bool,
        append: bool,
        truncate: bool,
    },
}

impl std::fmt::Debug for IrisRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrisRequest::DontTrustMeAnymore => write!(f, "DontTrustMeAnymore"),
            IrisRequest::OpenFile { path, read, write, create, append, truncate } => write!(f,
                "OpenFile({}{}{}{}{}{})", OsStr::from_bytes(&path[..]).to_string_lossy(),
                if *read { ", read" } else { "" },
                if *write { ", write" } else { "" },
                if *create { ", create" } else { "" },
                if *append { ", append" } else { "" },
                if *truncate { ", truncate" } else { "" }),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum IrisResponse {
    YouAreNotTrustworthyAnymore,
    UnexpectedRequest,
    ReturnCode(usize),
    DeniedByPolicy,
}

// Name of the environment variable used to pass the socket file descriptor number
// from brokers to workers.
const LIBIRIS_SOCKET_FD_ENV_NAME: &str = "IRIS_SOCK_FD";

// Maximum number of bytes in a single IPC message (request/response to or from a broker)
// Chosen to fit MAX_PATH (260 * sizeof(WCHAR)) on Windows + serialization headers.
const LIBIRIS_IPC_MESSAGE_MAX_SIZE: usize = 1024;

const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 26] = [
    "read",
    "write",
    "readv",
    "writev",
    "recvmsg",
    "sendmsg",
    "fstat",
    "_llseek",
    "_newselect",
    "accept",
    "accept4",
    "close",
    "sigaltstack",
    "munmap",
    "nanosleep",
    "exit_group",
    "restart_syscall",
    "rt_sigreturn",
    "rt_sigaction", // FIXME: should really be handled separately, to hook rt_sigaction(SIGSYS,..)
    "getpid",
    "gettid",
    "alarm",
    "arch_prctl",
    "brk",
    "cacheflush",
    "close_range",
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
    // Option filled the first time a wait_for_exit() is called and succeeds
    exit_code: Option<i32>,
}

struct IrisWorkerParam {
    exe: String,
    argv: Vec<String>,
    envp: Vec<String>,
    request_socket: UnixSocket,
    execve_socket: UnixSocket,
}

impl Drop for IrisWorker {
    fn drop(&mut self) {
        if !self.has_exited() {
            panic!("IrisWorker dropped out of scope without proper error handling through wait_for_exit()");
        }
    }
}

impl IrisWorker {
    pub fn new(policy: &IrisPolicy, exe: &str, argv: &[&str], envp: &[&str]) -> Result<Self, String>
    {
        if argv.len() < 1 {
            return Err("Invalid argument passed to IrisWorker::new(): empty argv".to_owned());
        }

        println!(" [.] Creating worker from PID={}", std::process::id());

        // Allocate a stack for the child to execute on
        let mut stack = vec![0; DEFAULT_WORKER_STACK_SIZE];
        let stack_ptr = stack.as_mut_ptr().wrapping_add(DEFAULT_WORKER_STACK_SIZE) as *mut c_void;
    
        // Allocate a socketpair for the child to send syscall requests to us
        let (child_request_socket, mut broker_request_socket) = UnixSocket::new(false)?;
        // Allocate a socketpair to detect any execve() error during worker startup, using CLOEXEC behaviour on these sockets
        let (child_execve_socket, mut broker_execve_socket) = UnixSocket::new(true)?;
    
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
            .reject_trailing_bytes()
            .with_limit(1*1024*1024);
    
        if let Ok(bytes) = broker_execve_socket.recvmsg() {
            if bytes.len() > 0 {
                match bincode_options.deserialize::<i32>(&bytes) {
                    Ok(errno) => return Err(format!("Worker execve(\"{}\") failed with error {}", exe, errno)),
                    Err(e) => return Err(format!("Worker probably failed to execute, cannot deserialize message from execve socket: {:?}", e)),
                }
            }
        }
    
        // TODO: if CLONE_NEWNS failed and CAP_SYS_CHROOT is held, chroot to an empty directory
        // TODO: ensure sandboxed children don't have the (theoretical) right to ptrace() each others (if seccomp fails). Otherwise, prctl(undumpable) like chromium.
        let policy = policy.clone();
    
        let manager_thread_builder = thread::Builder::new().name(format!("iris_{}_manager", pid)).stack_size(32 * 1024);
        let manager_thread_handle = manager_thread_builder.spawn(move || -> Result<(), String> {
            let jobs: VecDeque<IrisRequest> = VecDeque::new();
            let message = match broker_request_socket.recvmsg() {
                Ok(message) => message,
                Err(e) => return Err(format!("Failed to read initial request from worker: {:?}, did it exit before calling libiris_dont_trust_me_anymore() ?", e)),
            };
            match bincode_options.deserialize(&message) {
                Ok(IrisRequest::DontTrustMeAnymore) => (),
                other => return Err(format!("Failed to deserialize initial request from worker: {:?} , did it exit before calling libiris_dont_trust_me_anymore() ?", other)),
            };
            let message = bincode_options.serialize(&IrisResponse::YouAreNotTrustworthyAnymore).expect("Failed to serialize initial response");
    	if let Err(e) = broker_request_socket.sendmsg_with_fd(&message, None) {
                return Err(format!("Failed to serialize initial response to worker: {:?}, did it exit before calling libiris_dont_trust_me_anymore() ?", e));
            }
            loop {
                let bytes = match broker_request_socket.recvmsg() {
                    Ok(bytes) => bytes,
                    Err(e) => return Err(format!("Failed to read request from worker: {}", e)),
                };
                if bytes.is_empty() {
                    break;
                }
                let request: IrisRequest = match bincode_options.deserialize(&bytes) {
                    Ok(r) => r,
                    Err(e) => return Err(format!("Failed to deserialize request from worker: {}", e)),
                };
                let (response, fd) = match request {
                    IrisRequest::OpenFile { path, read, write, create, append, truncate } => {
                        let path_nul = match CString::new(path) {
                            Ok(s) => s,
                            Err(e) => {
                                println!(" [!] Worker requested open() of invalid path ({})", e);
                                break;
                            },
                        };
                        let mut flags = match (read, write) {
                            (true, true) => libc::O_RDWR,
                            (true, false) => libc::O_RDONLY,
                            (false, true) => libc::O_WRONLY,
                            _ => {
                                println!(" [!] Worker requested open({:?}) with no read nor write", path_nul);
                                break;
                            },
                        };
                        if create {
                            flags |= libc::O_CREAT;
                        }
                        if append {
                            flags |= libc::O_APPEND;
                        }
                        if truncate {
                            flags |= libc::O_TRUNC;
                        }
                        if (read && !policy.is_file_path_allowed_for_read(&path_nul)) ||
                           ((write || append || create || truncate) && !policy.is_file_path_allowed_for_write(&path_nul))
                        {
                            (IrisResponse::DeniedByPolicy, None)
                        }
                        else {
                            let res = unsafe { libc::open(path_nul.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0) };
                            if res < 0 {
                                println!(" [!] Worker requested open({:?}, {}) which failed with error {}", path_nul, flags, res);
                                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                                (IrisResponse::ReturnCode(errno.try_into().unwrap()), None)
                            }
                            else {
                                println!(" [.] Granted, sending file descriptor");
                                (IrisResponse::ReturnCode(0), Some(res))
                            }
                        }
                    },
                    _ => {
                        println!(" [!] Discarding unexpected request from worker: {:?}", request);
                        (IrisResponse::UnexpectedRequest, None)
                    },
                };
                let bytes = match bincode_options.serialize(&response) {
                    Ok(bytes) => bytes,
                    Err(e) => return Err(format!("Failed to serialize response for worker: {}", e)),
                };
                if let Err(e) = broker_request_socket.sendmsg_with_fd(&bytes, fd) {
                    return Err(format!("Failed to send response to worker: {}", e));
                }
            }
            println!(" [.] Worker closed its side of the communication socket, manager closing");
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
            exit_code: None,
        })
    }

    pub fn wait_for_exit(&mut self) -> Result<(), String> {
        if let Some(handle) = self.manager_thread_handle.take() {
            println!(" [.] Waiting for manager thread to exit");
            match handle.join() {
                Ok(Ok(())) => (),
                Ok(Err(e)) => return Err(format!("Manager thread exited with error: {}", e)),
                Err(e) => return Err(format!("Error while waiting for manager thread to exit: {:?}", e)),
            }
            let mut status: c_int = 0;
            let pid: i32 = self.pid.try_into().unwrap();
            let res = unsafe { libc::waitpid(pid, &mut status as *mut c_int, libc::__WALL) };
            // Ignore ECHILD errors which can occur if the child exits right away before waitpid() starts
            if res != pid {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                    return Err("Failed to wait for worker process to exit, another thread in the application already called wait() or waitpid()".to_owned());
                }
                return Err(format!("Failed to wait for worker PID={} to exit: {}", pid, std::io::Error::last_os_error()));
            }
            if libc::WIFEXITED(status) {
                println!(" [.] Worker reaped successfully, exited with code {}", libc::WEXITSTATUS(status));
                self.exit_code = Some(libc::WEXITSTATUS(status));
            } else if libc::WIFSIGNALED(status) {
                println!(" [.] Worker reaped successfully, killed by signal {}", libc::WTERMSIG(status));
                self.exit_code = Some(128 + libc::WTERMSIG(status));
            } else {
                println!(" [.] Worker reaped successfully, unknown exit reason (status {})", status);
                self.exit_code = Some(status);
            }
        }
        else {
            println!(" [.] Manager thread already exited");
        }
        Ok(())
    }

    pub fn has_exited(&self) -> bool {
        self.manager_thread_handle.is_none() || self.exit_code.is_some()
    }

    pub fn get_exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

extern "C" fn worker_entrypoint(arg: *mut c_void) -> c_int
{
    // Cast the argument back to the boxed IrisWorkerParam it was.
    // worker_entrypoint() must only be used by libiris_worker_new() so it is safe to take ownership here.
    let mut arg = unsafe { Box::from_raw(arg as *mut IrisWorkerParam) };
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
    let request_socket_fd = arg.request_socket.as_raw_fd();
    let request_socket_env_var = CString::new(format!("{}={}", LIBIRIS_SOCKET_FD_ENV_NAME, request_socket_fd)).unwrap();
    let envp: Vec<*const i8> = envp.iter().map(|x| x.as_ptr() as *const i8).chain(vec![request_socket_env_var.as_ptr(), null()]).collect();
    
    unsafe { libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };

    let execve_errno: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
    let message = bincode_options.serialize(&execve_errno).expect("Failed to serialize execve() error to broker process");
    arg.execve_socket.sendmsg_with_fd(&message, None).expect("Failed to forward execve() error to broker process");
    execve_errno as c_int
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

fn get_response_from_broker(request: IrisRequest, fd: Option<i32>) -> (IrisResponse, Option<i32>)
{
    let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
    let mut sock = libiris_get_broker_socket().unwrap();
    let bytes = bincode_options.serialize(&request).expect("Failed to serialize request for broker");
    println!(" [.] Sending request to broker: {:?}", &request);
    sock.sendmsg_with_fd(&bytes, fd).expect("Failed to send syscall request to broker");
    let (bytes, fd) = sock.recvmsg_with_fd().expect("Failed to read response from broker");
    let response = bincode_options.deserialize(&bytes).expect("Failed to deserialize response from broker");
    println!(" [.] Received response from broker: {:?}", &response);
    (response, fd)
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
    
    let ucontext = ucontext as *mut libc::ucontext_t;
    let syscall_nr = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] };

    // /!\ Memory / print are unsafe in syscall handler, just for debugging purposes here
    let msg = format!(" [.] Syscall nr={} ({}, {}, {}, {}, {}, {}) tried, needs broker proxying\n",
        syscall_nr,
        unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RDI as usize] },
        unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RSI as usize] },
        unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RDX as usize] },
        unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_R10 as usize] },
        unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_R8 as usize] },
        unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_R9 as usize] },
    );
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };

    let response_code = match syscall_nr {
        libc::SYS_access => {
            let path = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RDI as usize] };
            let path = unsafe { CStr::from_ptr(path as *const libc::c_char) }.to_owned();
            let mode = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RSI as usize] } as i32;
            println!(" [.] access({:?}, {}) called", path, mode);
            if mode == libc::F_OK {
                let request = IrisRequest::OpenFile {
                    path: path.to_bytes().to_owned(),
                    read: true,
                    write: false,
                    create: false,
                    append: false,
                    truncate: false,
                };
                match get_response_from_broker(request, None) {
                    (IrisResponse::ReturnCode(0), Some(fd)) => {
                        unsafe { libc::close(fd); }
                        0
                    },
                    (IrisResponse::ReturnCode(n), None) if n != libc::EACCES.try_into().unwrap() => -(n as i64),
                    (IrisResponse::ReturnCode(_), None) | (IrisResponse::DeniedByPolicy, None) => {
                        // Retry with write-only access
                        let request = IrisRequest::OpenFile {
                            path: path.to_bytes().to_owned(),
                            read: false,
                            write: true,
                            create: false,
                            append: false,
                            truncate: false,
                        };
                        match get_response_from_broker(request, None) {
                            (IrisResponse::ReturnCode(0), Some(fd)) => {
                                unsafe { libc::close(fd); }
                                0
                            },
                            (IrisResponse::ReturnCode(n), None) => -(n as i64),
                            (IrisResponse::DeniedByPolicy, None) => -(libc::EACCES as i64),
                            err => panic!("Unexpected broker response: {:?}", err),
                        }
                    },
                    err => panic!("Unexpected broker response: {:?}", err),
                }
            }
            else {
                let request = IrisRequest::OpenFile {
                    path: path.to_bytes().to_owned(),
                    read: (mode & (libc::R_OK | libc::X_OK)) != 0,
                    write: (mode & libc::W_OK) != 0,
                    create: false,
                    append: false,
                    truncate: false,
                };
                match get_response_from_broker(request, None) {
                    (IrisResponse::ReturnCode(0), Some(fd)) => {
                        unsafe { libc::close(fd); }
                        0
                    },
                    (IrisResponse::ReturnCode(n), None) if n != libc::EACCES.try_into().unwrap() => -(n as i64),
                    (IrisResponse::ReturnCode(_), None) | (IrisResponse::DeniedByPolicy, None) => -(libc::EACCES as i64),
                    err => panic!("Unexpected broker response: {:?}", err),
                }
            }
        },
/*
        libc::SYS_bind => {
        },
        libc::SYS_chdir => {
            // TODO: emulate in worker, don't let it chdir() anywhere
        },
        libc::SYS_chmod => {
        },
        libc::SYS_chown => {
        },
//        libc::SYS_chown32 => {
//        },
        libc::SYS_connect => {
        },
        libc::SYS_creat => {
        },
        libc::SYS_faccessat => {
        },
//        libc::SYS_faccessat2 => {
//        },
        libc::SYS_fchdir => {
        },
        libc::SYS_stat => {
            
        },
        // TODO: emulate SYS_capset to be a no-op?
        libc::SYS_capget => {
            
        }
*/
        // TODO: SYS_add_key KEY_SPEC_THREAD_KEYRING, KEY_SPEC_PROCESS_KEYRING
        // TODO: kill(0), kill(-1) redirect to kill(getpid())
        // TODO: openat2()
        libc::SYS_open => {
            // TODO: resolve the path given relative to CWD if it is relative
            let path = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RDI as usize] };
            let path = unsafe { CStr::from_ptr(path as *const libc::c_char) }.to_owned();
            let flags = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RSI as usize] } as i32;
            println!(" [.] Requesting access to file path {:?}", path);
            let request = IrisRequest::OpenFile {
                path: path.to_bytes().to_owned(),
                read: (flags & (libc::O_WRONLY)) == 0,
                write: (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0,
                create: (flags & libc::O_CREAT) != 0,
                append: (flags & libc::O_APPEND) != 0,
                truncate: (flags & libc::O_TRUNC) != 0,
            };
            let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
            let bytes = match bincode_options.serialize(&request) {
                Ok(bytes) => bytes,
                Err(e) => panic!("Failed to serialize syscall request into socket: {:?}", e),
            };
            let mut sock = libiris_get_broker_socket().unwrap();
            sock.sendmsg_with_fd(&bytes, None).expect("Failed to send syscall request to broker");
            let (bytes, fd) = sock.recvmsg_with_fd().expect("Failed to read response from broker");
            let return_code = match (bincode_options.deserialize(&bytes), fd) {
                (Ok(IrisResponse::ReturnCode(0)), Some(fd)) => fd as i64,
                (Ok(IrisResponse::ReturnCode(n)), None) => -(n as i64),
                (Ok(IrisResponse::DeniedByPolicy), None) => -(libc::EPERM as i64),
                err => panic!("Failed to deserialize syscall response: {:?}", err),
            };
            return_code
        },
        libc::SYS_openat => {
            // TODO: resolve the file descriptor or CWD if given as argument and path isn't absolute.
            // /!\ readlink(/proc/self/fd/%d) might not be up to date: may have been moved after being opened. Use fstat(fd)?
            let path = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RSI as usize] };
            let flags = unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RDX as usize] } as i32;
            let path = unsafe { CStr::from_ptr(path as *const libc::c_char) }.to_owned();
            println!(" [.] Requesting access to file path {:?}", path);
            let request = IrisRequest::OpenFile {
                path: path.to_bytes().to_owned(),
                read: (flags & (libc::O_WRONLY)) == 0,
                write: (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0,
                create: (flags & libc::O_CREAT) != 0,
                append: (flags & libc::O_APPEND) != 0,
                truncate: (flags & libc::O_TRUNC) != 0,
            };
            let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
            let bytes = match bincode_options.serialize(&request) {
                Ok(bytes) => bytes,
                Err(e) => panic!("Failed to serialize syscall request into socket: {:?}", e),
            };
            let mut sock = libiris_get_broker_socket().unwrap();
            sock.sendmsg_with_fd(&bytes, None).expect("Failed to send syscall request to broker");
            let (bytes, fd) = sock.recvmsg_with_fd().expect("Failed to read response from broker");
            let return_code = match (bincode_options.deserialize(&bytes), fd) {
                (Ok(IrisResponse::ReturnCode(0)), Some(fd)) => fd as i64,
                (Ok(IrisResponse::ReturnCode(n)), None) => -(n as i64),
                (Ok(IrisResponse::DeniedByPolicy), None) => -(libc::EPERM as i64),
                err => panic!("Failed to deserialize syscall response: {:?}", err),
            };
            return_code
        }
        _ => {
            println!(" [!] Syscall not supported yet, denied by default");
            -(libc::EPERM as i64)
        }
    };
    println!(" [.] Syscall result: {}", response_code);
    unsafe { (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] = response_code; }
}

pub fn libiris_dont_trust_me_anymore() -> Result<(), String>
{
    let mut sock = match libiris_get_broker_socket() {
        Some(s) => s,
        None => return Err("Could not find broker communication socket in environment variables, is this really a sandboxed process?".to_owned()),
    };
    let bincode_options = bincode::DefaultOptions::new().with_fixint_encoding();
    let bytes = bincode_options.serialize(&IrisRequest::DontTrustMeAnymore).expect("Failed to serialize initial message for broker");
    sock.sendmsg_with_fd(&bytes, None).expect("Failed to send initial message to broker");

    let bytes = sock.recvmsg().expect("Failed to read initial response from broker");
    match bincode_options.deserialize(&bytes) {
        Ok(IrisResponse::YouAreNotTrustworthyAnymore) => (),
        other => panic!("Failed to deserialize initial response from broker socket: {:?}", other),
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
        let syscall_nr = match get_syscall_number(&syscall_name) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(" [.] Unable to find syscall {} : {}", syscall_name, e);
                continue;
            },
        };
        println!(" [.] Allowing syscall {} / {}", syscall_name, syscall_nr);
        let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 0) };
        if res != 0 {
            println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, {}) failed with code {}", syscall_name, -res);
        }
    }

    // Add special case handling for kill() on ourselves only (useful for e.g. raise())
    let syscall_nr = get_syscall_number("kill").unwrap();
    println!(" [.] Allowing syscall kill / {} on ourselves only", syscall_nr);
    let mypid = std::process::id();
    let a0_pid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: mypid.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, kill, SCMP_A0(SCMP_CMP_EQ, getpid())) failed with code {}", -res);
    }

    let syscall_nr = get_syscall_number("tgkill").unwrap();
    println!(" [.] Allowing syscall tgkill / {} on ourselves only", syscall_nr);
    let a0_pid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: mypid.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, tgkill, SCMP_A0(SCMP_CMP_EQ, getpid())) failed with code {}", -res);
    }
    
    let syscall_nr = get_syscall_number("tkill").unwrap();
    println!(" [.] Allowing syscall tkill / {} on ourselves only", syscall_nr);
    let mytid = unsafe { libc::syscall(libc::SYS_gettid) };
    let a0_tid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: mytid.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 1, a0_tid_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, tkill, SCMP_A0(SCMP_CMP_EQ, gettid())) failed with code {}", -res);
    }

    let res = unsafe { seccomp_load(filter) };
    if res != 0 {
        return Err(format!("seccomp_load() failed with error {}", -res));
    }

    unsafe { seccomp_release(filter) };

    println!(" [.] Worker ready to handle untrusted data");
    Ok(())
}

