use iris::libiris_dont_trust_me_anymore;

fn main() {
    println!(" [.] Worker subprocess started successfully, exiting with code 42");
    libiris_dont_trust_me_anymore().expect("Unable to lower privileges");
    unsafe { libc::raise(libc::SIGILL); }
    std::process::exit(1);
}

