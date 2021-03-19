use iris::libiris_worker_new;

#[test]
fn execve_errors_propagate() {
    println!(" [.] Broker started");
    match libiris_worker_new("/nonexistentbinary", &["iris-test"], &[]) {
        Err(_) => (),
        Ok(_) => panic!("libiris_worker_new(/nonexistentbinary) succeeded"),
    }
}

