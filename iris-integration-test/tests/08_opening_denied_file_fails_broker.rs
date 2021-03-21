use iris::{IrisPolicy, IrisWorker};

#[test]
fn opening_denied_file_fails() {
    println!(" [.] Broker started");
    let policy = IrisPolicy::new();
    let mut worker = IrisWorker::new(&policy, "../target/debug/08_opening_denied_file_fails_worker", &["iris-test"], &[]).expect("Error in worker creation");
    println!(" [.] Worker creation succeeded, waiting for exit...");
    worker.wait_for_exit().expect("Error when waiting for worker to exit");
    let exit_code = worker.get_exit_code().expect("Error when getting worker exit code");
    assert_eq!(exit_code, 0, "Non-zero exit code, worker crashed");
}

