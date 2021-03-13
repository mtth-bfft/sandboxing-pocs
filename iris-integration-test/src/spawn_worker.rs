use iris::libiris_dont_trust_me_anymore;

fn main() {
    println!(" [+] Subprocess started successfully");
    match libiris_dont_trust_me_anymore() {
        Ok(_) => println!(" [+] Subprocess gave up on its privileges successfully"),
        Err(e) => panic!(" [!] Error while dropping privileges: {}", e),
    };
    println!(" [+] Subprocess exiting successfully");
}

