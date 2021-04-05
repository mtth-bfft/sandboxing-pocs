use iris::{IrisPolicy, IrisWorker};
use std::ffi::CString;
use std::fs::File;

#[test]
fn access_broker() {
    File::create("/tmp/iris_test_09_existing_nothing.flag").unwrap();
    File::create("/tmp/iris_test_09_existing_r.flag").unwrap();
    File::create("/tmp/iris_test_09_existing_w.flag").unwrap();
    File::create("/tmp/iris_test_09_existing_rw.flag").unwrap();
    let mut policy = IrisPolicy::new();
    policy.allow_file_path_for_read(&CString::new("/tmp/iris_test_09_existing_r.flag").unwrap()).unwrap();
    policy.allow_file_path_for_read(&CString::new("/tmp/iris_test_09_missing_r.flag").unwrap()).unwrap();
    policy.allow_file_path_for_write(&CString::new("/tmp/iris_test_09_existing_w.flag").unwrap()).unwrap();
    policy.allow_file_path_for_write(&CString::new("/tmp/iris_test_09_missing_w.flag").unwrap()).unwrap();
    policy.allow_file_path_for_read(&CString::new("/tmp/iris_test_09_existing_rw.flag").unwrap()).unwrap();
    policy.allow_file_path_for_read(&CString::new("/tmp/iris_test_09_missing_rw.flag").unwrap()).unwrap();
    policy.allow_file_path_for_write(&CString::new("/tmp/iris_test_09_existing_rw.flag").unwrap()).unwrap();
    policy.allow_file_path_for_write(&CString::new("/tmp/iris_test_09_missing_rw.flag").unwrap()).unwrap();
    let mut worker = IrisWorker::new(&policy, "../target/debug/09_access_worker", &["iris-test"], &[]).expect("Error in worker creation");
    worker.wait_for_exit().expect("Error when waiting for worker to exit");
    let exit_code = worker.get_exit_code().expect("Error when getting worker exit code");
    assert_eq!(exit_code, 0, "Non-zero exit code, worker crashed");
}

