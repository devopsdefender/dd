mod password_hash;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("DevOps Defender Admin CLI");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  dd-admin hash-password    Generate a bcrypt hash for an admin password");
        eprintln!();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "hash-password" => password_hash::run(),
        other => {
            eprintln!("Unknown command: {other}");
            eprintln!("Available commands: hash-password");
            std::process::exit(1);
        }
    }
}
