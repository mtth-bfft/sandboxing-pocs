use iris::libiris_worker_new;

#[test]
fn get_exit_code_works_after_exit() {
    println!(" [.] Broker started");
    let mut worker = libiris_worker_new("../target/debug/05_get_exit_code_works_after_exit_worker", &["iris-test"], &[]).expect("Error in worker creation");
    println!(" [.] Worker creation succeeded");
    worker.wait_for_exit().expect("Error when waiting for worker exit");
    assert_eq!(worker.get_exit_code(), Some(42));
}
