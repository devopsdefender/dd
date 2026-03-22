/// Generate a bcrypt hash for an admin password.
pub fn run() {
    eprintln!("Enter admin password:");

    let password = rpassword::read_password().expect("failed to read password");

    if password.is_empty() {
        eprintln!("Error: password cannot be empty");
        std::process::exit(1);
    }

    let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST).expect("bcrypt hash failed");

    println!("{hash}");
    eprintln!();
    eprintln!("Set this as DD_CP_ADMIN_PASSWORD in your environment.");
}
