use iris::libiris_worker_new;

#[test]
fn drop_privileges() {
    println!(" [.] Broker started");
    match libiris_worker_new("./target/debug/cannot_open_file_worker", &["iris-test"], &[]) {
        Ok(_) => println!(" [+] Worker creation succeeded"),
        Err(e) => panic!(" [!] Error in worker creation: {}", e),
    };
    println!(" [.] Broker exiting");
}

