use iris::{IrisPolicy, IrisWorker};

#[test]
fn execve_errors_propagate() {
    println!(" [.] Broker started");
    let policy = IrisPolicy::new();
    match IrisWorker::new(&policy, "/nonexistentbinary", &["iris-test"], &[]) {
        Err(_) => (),
        Ok(_) => panic!("libiris_worker_new(/nonexistentbinary) succeeded"),
    }
}

