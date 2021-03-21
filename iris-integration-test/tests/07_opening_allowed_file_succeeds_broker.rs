use iris::{IrisPolicy, IrisWorker};
use std::ffi::CString;

#[test]
fn opening_allowed_file_succeeds() {
    println!(" [.] Broker started");
    let mut policy = IrisPolicy::new();
    policy.allow_file_path_for_read(&CString::new("/etc/hosts").unwrap());
    let mut worker = IrisWorker::new(&policy, "../target/debug/07_opening_allowed_file_succeeds_worker", &["iris-test"], &[]).expect("Error in worker creation");
    println!(" [.] Worker creation succeeded, waiting for exit...");
    worker.wait_for_exit().expect("Error when waiting for worker to exit");
    let exit_code = worker.get_exit_code().expect("Error when getting worker exit code");
    assert_eq!(exit_code, 0, "Non-zero exit code, worker crashed");
}

