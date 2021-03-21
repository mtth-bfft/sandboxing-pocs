use iris::{IrisPolicy, IrisWorker};

#[test]
#[should_panic(expected="error handling through wait_for_exit")]
fn forgetting_wait_panics() {
    println!(" [.] Broker started");
    let policy = IrisPolicy::new();
    let worker = match IrisWorker::new(&policy, "../target/debug/02_forgetting_wait_panics_worker", &["iris-test"], &[]) {
        Ok(worker) => worker,
        Err(e) => { println!(" [!] Error in worker creation: {}", e); std::process::exit(1); },
    };
    println!(" [.] Worker creation succeeded, dropping it...");
    std::mem::drop(worker);
    println!(" [!] Should not have reached this point");
    std::process::exit(1);
}

