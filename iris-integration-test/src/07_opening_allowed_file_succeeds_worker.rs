use iris::libiris_dont_trust_me_anymore;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::io::Read;
use std::ffi::CString;
use std::convert::TryInto;

fn main() {
    libiris_dont_trust_me_anymore().expect("Error while dropping privileges");
    println!(" [.] Privileges dropped");

    println!(" [.] Attempting to open() absolute path...");
    let flag_path = CString::new("/tmp/iris_test_07.flag").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_open, flag_path.as_ptr(), libc::O_RDONLY, 0) };
    let fd: i32 = fd.try_into().unwrap();
    assert!(fd > 0, "open() failed");
    let mut file = unsafe { File::from_raw_fd(fd.try_into().unwrap()) };
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("Failed to read from file descriptor");
    unsafe { libc::close(fd); }
    assert_eq!(contents, b"FLAG");
}

