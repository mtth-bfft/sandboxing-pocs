use iris::{IrisWorker, IrisPolicy};

#[test]
fn spawn() {
    println!(" [.] Broker started");
    let policy = IrisPolicy::new();
    let mut worker = IrisWorker::new(&policy, "../target/debug/01_spawn_worker", &["iris-test"], &[]).expect("Error in worker creation");
    println!(" [+] Worker creation succeeded");
    worker.wait_for_exit().expect("Error when waiting for worker exit");
    println!(" [+] Worker exited successfully");
    println!(" [.] Broker exiting");
}

