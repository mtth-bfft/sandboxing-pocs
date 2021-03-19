use iris::libiris_dont_trust_me_anymore;

fn main() {
    libiris_dont_trust_me_anymore().expect("Error while dropping privileges");
    println!(" [.] Attempting to open file without privileges...");
    let err = std::fs::read_to_string("/etc/resolv.conf").expect_err("File shouldn't have been opened");
    println!(" [+] Successful, denied: {}", err);
}

