use iris::libiris_dont_trust_me_anymore;

fn main() {
    println!(" [+] Subprocess started successfully");
    match libiris_dont_trust_me_anymore() {
        Ok(_) => println!(" [+] Subprocess gave up on its privileges successfully"),
        Err(e) => println!(" [!] Error while dropping privileges: {}", e),
    };
    match std::fs::File::open("/etc/hosts") {
        Ok(_) => panic!("Opening /etc/hosts should have failed"),
        Err(e) => println!(" [+] Opening /etc/hosts failed with error: {}", e),
    };
    println!(" [+] Subprocess exiting successfully");
}

