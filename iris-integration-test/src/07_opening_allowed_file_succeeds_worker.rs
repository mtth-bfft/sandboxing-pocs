use iris::libiris_dont_trust_me_anymore;

fn main() {
    libiris_dont_trust_me_anymore().expect("Error while dropping privileges");
    println!(" [.] Attempting to open file without privileges...");
    let contents = std::fs::read_to_string("/etc/hosts").expect("Unable to open file");
    println!(" [+] Successful:\n{}", contents);
}

