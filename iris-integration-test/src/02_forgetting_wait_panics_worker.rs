use iris::libiris_dont_trust_me_anymore;

fn main() {
    println!(" [.] Worker subprocess started successfully");
    match libiris_dont_trust_me_anymore() {
        Ok(_) => println!(" [.] Subprocess gave up on its privileges successfully"),
        Err(e) => panic!(" [!] Error while dropping privileges: {}", e),
    };
    println!(" [.] Worker subprocess exiting successfully");
}

