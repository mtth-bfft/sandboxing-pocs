use iris::libiris_worker_new;

#[test]
fn forgetting_lockdown_returns_error() {
    println!(" [.] Broker started");
    let mut worker = libiris_worker_new("../target/debug/03_forgetting_lockdown_returns_error_worker", &["iris-test"], &[]).expect("Error in worker creation");
    println!(" [.] Worker creation succeeded, waiting for exit...");
    match worker.wait_for_exit() {
        Err(e) if e.contains("dont_trust_me_anymore") => (),
        other => panic!("wait_for_exit() returned {:?}", other),
    }
}

