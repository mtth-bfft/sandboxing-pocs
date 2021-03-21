use iris::{IrisPolicy, IrisWorker};

#[test]
fn get_exit_code_works_after_exit() {
    println!(" [.] Broker started");
    let policy = IrisPolicy::new();
    let mut worker = IrisWorker::new(&policy, "../target/debug/05_get_exit_code_works_after_exit_worker", &["iris-test"], &[]).expect("Error in worker creation");
    println!(" [.] Worker creation succeeded");
    worker.wait_for_exit().expect("Error when waiting for worker exit");
    assert_eq!(worker.get_exit_code(), Some(42));
}

