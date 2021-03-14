use iris::libiris_worker_new;

#[test]
fn spawn() {
    println!(" [.] Broker started");
    let mut worker = libiris_worker_new("../target/debug/01_spawn_worker", &["iris-test"], &[]).expect("Error in worker creation");
    println!(" [+] Worker creation succeeded");
    worker.wait_for_exit().expect("Error when waiting for worker exit");
    println!(" [+] Worker exited successfully");
    println!(" [.] Broker exiting");
}

