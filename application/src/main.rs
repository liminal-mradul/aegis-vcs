use blake3;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore; // Added for fill_bytes
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path};
use base58::ToBase58;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize, Debug)]
struct Commit {
    id: String,
    author: String,
    timestamp: String,
    message: String,
    changes: Vec<String>,
    signature: String,
    public_key: String,
}

fn init_repo() {
    if Path::new(".aegis").exists() {
        println!("Repository already exists!");
        return;
    }
    fs::create_dir(".aegis").unwrap();
    fs::create_dir(".aegis/commits").unwrap();

    // Generate key pair using manual byte generation
    let mut secret_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_key_bytes);
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let verifying_key = signing_key.verifying_key();

    fs::write(".aegis/secret.key", signing_key.to_bytes()).unwrap();
    fs::write(".aegis/public.key", verifying_key.to_bytes()).unwrap();

    println!("Initialized empty Aegis repository.");
}

fn commit(message: String) {
    if !Path::new(".aegis").exists() {
        println!("Not a repository. Run `init` first.");
        return;
    }

    let mut buf = Vec::new();
    for entry in WalkDir::new(".")
        .into_iter()
        .filter_entry(|e| !e.path().starts_with(".aegis"))
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
    {
        let mut file = fs::File::open(entry.path()).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        buf.extend_from_slice(&blake3::hash(&contents).as_bytes()[..]);
    }

    let commit_id = blake3::hash(&buf).to_hex().to_string();

    let author = whoami::realname();
    let timestamp = Utc::now().to_rfc3339();

    let changes = vec!["(file diff tracking not implemented yet)".to_string()];

    let signing_key_bytes = fs::read(".aegis/secret.key").unwrap();
    let signing_key = SigningKey::from_bytes(
        &signing_key_bytes
            .as_slice()
            .try_into()
            .expect("Invalid key length (expected 32 bytes)"),
    );
    let signature: Signature = signing_key.sign(commit_id.as_bytes());

    let commit_data = Commit {
        id: commit_id.clone(),
        author,
        timestamp,
        message,
        changes,
        signature: signature.to_bytes().to_base58(),
        public_key: signing_key.verifying_key().to_bytes().to_base58(),
    };

    let yaml = serde_yaml::to_string(&commit_data).unwrap();
    fs::write(format!(".aegis/commits/{}.yaml", commit_id), yaml).unwrap();
    fs::write(".aegis/HEAD", &commit_id).unwrap();

    println!("Committed: {}", commit_id);
}

fn log_history() {
    if !Path::new(".aegis/commits").exists() {
        println!("No commits found.");
        return;
    }

    for entry in fs::read_dir(".aegis/commits").unwrap() {
        let entry = entry.unwrap();
        let contents = fs::read_to_string(entry.path()).unwrap();
        println!("{}", contents);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: aegis-vcs <init|commit|log> [message]");
        return;
    }

    match args[1].as_str() {
        "init" => init_repo(),
        "commit" => {
            if args.len() < 3 {
                println!("Commit message required.");
            } else {
                commit(args[2..].join(" "));
            }
        }
        "log" => log_history(),
        _ => println!("Unknown command."),
    }
}
