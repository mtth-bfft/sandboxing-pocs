use iris::libiris_dont_trust_me_anymore;
use std::ffi::CString;
use std::convert::TryInto;

fn main() {
    libiris_dont_trust_me_anymore().expect("Error while dropping privileges");

    let tests = vec![
        ("/tmp/iris_test_09_existing_nothing.flag", libc::F_OK, libc::EACCES),
        ("/tmp/iris_test_09_existing_nothing.flag", libc::R_OK, libc::EACCES),
        ("/tmp/iris_test_09_existing_nothing.flag", libc::W_OK, libc::EACCES),
        ("/tmp/iris_test_09_existing_r.flag",       libc::F_OK, 0),
        ("/tmp/iris_test_09_existing_r.flag",       libc::R_OK, 0),
        ("/tmp/iris_test_09_existing_r.flag",       libc::W_OK, libc::EACCES),
        ("/tmp/iris_test_09_existing_w.flag",       libc::F_OK, 0),
        ("/tmp/iris_test_09_existing_w.flag",       libc::R_OK, libc::EACCES),
        ("/tmp/iris_test_09_existing_w.flag",       libc::W_OK, 0),
        ("/tmp/iris_test_09_existing_rw.flag",      libc::F_OK, 0),
        ("/tmp/iris_test_09_existing_rw.flag",      libc::R_OK, 0),
        ("/tmp/iris_test_09_existing_rw.flag",      libc::W_OK, 0),
        ("/tmp/iris_test_09_missing_nothing.flag",  libc::F_OK, libc::EACCES),
        ("/tmp/iris_test_09_missing_r.flag",        libc::F_OK, libc::ENOENT),
        ("/tmp/iris_test_09_missing_r.flag",        libc::R_OK, libc::ENOENT),
        ("/tmp/iris_test_09_missing_r.flag",        libc::W_OK, libc::EACCES),
        ("/tmp/iris_test_09_missing_w.flag",        libc::F_OK, libc::ENOENT),
        ("/tmp/iris_test_09_missing_w.flag",        libc::R_OK, libc::EACCES),
        ("/tmp/iris_test_09_missing_w.flag",        libc::W_OK, libc::ENOENT),
        ("/tmp/iris_test_09_missing_rw.flag",       libc::F_OK, libc::ENOENT),
        ("/tmp/iris_test_09_missing_rw.flag",       libc::R_OK, libc::ENOENT),
        ("/tmp/iris_test_09_missing_rw.flag",       libc::W_OK, libc::ENOENT),
    ];

    for (path, mode, expected) in tests {
        let res = unsafe { libc::syscall(libc::SYS_access, CString::new(path).unwrap().as_ptr(), mode) };
        let res: i32 = if res < 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(1) } else { res.try_into().unwrap() };
        assert_eq!(res, expected, "access({}, {}) returned {} (expected {})", path, mode, res, expected);
    }
}

