use iris::libiris_worker_new;

#[test]
#[should_panic(expected="error handling through wait_for_exit")]
fn forgetting_wait_panics() {
    println!(" [.] Broker started");
    let worker = match libiris_worker_new("../target/debug/02_forgetting_wait_panics_worker", &["iris-test"], &[]) {
        Ok(worker) => worker,
        Err(e) => { println!(" [!] Error in worker creation: {}", e); std::process::exit(1); },
    };
    println!(" [.] Worker creation succeeded, dropping it...");
    std::mem::drop(worker);
    println!(" [!] Should not have reached this point");
    std::process::exit(1);
}

