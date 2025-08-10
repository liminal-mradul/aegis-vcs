use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base58::{FromBase58, ToBase58};
use blake3;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use whoami;

#[derive(Debug, thiserror::Error)]
enum AegisError {
    #[error("Repository not initialized")]
    NotInitialized,
    #[error("Invalid commit ID")]
    InvalidCommit,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Base58 decode error")]
    Base58DecodeError,
    #[error("Keypair bytes conversion error")]
    KeypairConversionError,
    #[error("Whoami error: {0}")]
    WhoamiError(#[from] io::Error),
    #[error("Path not found: {0}")]
    PathNotFound(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Author {
    name: String,
    email: String,
    uid: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Commit {
    id: String,
    parents: Vec<String>, 
    timestamp: DateTime<Utc>,
    author: Author,
    tree_hash: String,
    changes: Changes,
    message: String,
    signature: String,
    public_key: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Changes {
    added: Vec<String>,
    modified: Vec<String>,
    deleted: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Tree {
    entries: BTreeMap<String, String>, 
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Index {
    entries: BTreeMap<String, String>, 
}

struct Repository {
    path: PathBuf,
    aegis_dir: PathBuf,
    signing_key: SigningKey,
}

impl Repository {
    fn init(path: &Path) -> Result<Self> {
        let aegis_dir = path.join(".aegis");
        if aegis_dir.exists() {
            anyhow::bail!("Repository already exists");
        }

        fs::create_dir_all(aegis_dir.join("objects"))?;
        fs::create_dir_all(aegis_dir.join("trees"))?;
        fs::create_dir_all(aegis_dir.join("commits"))?;

        let signing_key = SigningKey::generate(&mut OsRng);
        let keypair_bytes = signing_key.to_keypair_bytes();
        fs::write(aegis_dir.join("keypair.bin"), &keypair_bytes)?;

        let index = Index::default();
        let index_bytes = serde_yaml::to_string(&index)?;
        fs::write(aegis_dir.join("index"), index_bytes)?;

        let config = r#"
hash_algorithm: blake3
signature_algorithm: ed25519
uid_length: 12
"#;
        fs::write(aegis_dir.join("config.yaml"), config)?;

        Ok(Self {
            path: path.to_path_buf(),
            aegis_dir,
            signing_key,
        })
    }

    fn open(path: &Path) -> Result<Self> {
        let aegis_dir = path.join(".aegis");
        if !aegis_dir.exists() {
            return Err(AegisError::NotInitialized.into());
        }

        let keypair_bytes = fs::read(aegis_dir.join("keypair.bin"))?;
        let signing_key = SigningKey::from_keypair_bytes(
            keypair_bytes.as_slice().try_into().map_err(|_| AegisError::KeypairConversionError)?,
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            aegis_dir,
            signing_key,
        })
    }

    fn add(&self, path_to_add: &str) -> Result<()> {
        let mut index = self.read_index()?;
        let file_path = self.path.join(path_to_add);

        if !file_path.exists() {
            if index.entries.remove(path_to_add).is_some() {
                println!("Removed: {}", path_to_add);
            } else {
                return Err(AegisError::PathNotFound(path_to_add.to_string()).into());
            }
        } else if file_path.is_file() {
            let content = fs::read(&file_path)?;
            let hash = self.store_blob(&content)?;
            index.entries.insert(path_to_add.to_string(), hash);
            println!("Staged: {}", path_to_add);
        } else if file_path.is_dir() {
            for entry in WalkDir::new(&file_path)
                .into_iter()
                .filter_entry(|e| !is_ignored(e.path()))
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
            {
                let relative_path = entry.path().strip_prefix(&self.path)?.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?.to_string();
                let content = fs::read(entry.path())?;
                let hash = self.store_blob(&content)?;
                index.entries.insert(relative_path, hash);
            }
            println!("Staged directory: {}", path_to_add);
        }
        self.write_index(&index)
    }

    fn commit(&self, message: &str) -> Result<String> {
        let head = self.get_head()?;
        let index = self.read_index()?;
        
        if index.entries.is_empty() {
            anyhow::bail!("Nothing to commit, working tree clean");
        }
        
        let tree_hash = self.create_tree_from_index(&index)?;
        let tree = self.load_tree(&tree_hash)?;

        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "localhost".to_string());
        let username = whoami::username();

        let author = Author {
            name: whoami::realname(),
            email: format!("{}@{}", username, hostname),
            uid: self.get_public_uid(),
        };

        let timestamp = Utc::now();
        let changes = self.compute_changes(head.as_deref(), &tree)?;

        let mut commit = Commit {
            id: String::new(),
            parents: head.map_or_else(|| vec![], |h| vec![h]),
            timestamp,
            author,
            tree_hash,
            changes: changes.clone(),
            message: message.to_string(),
            signature: String::new(),
            public_key: self.signing_key.verifying_key().to_bytes().to_base58(),
        };

        let commit_data_for_signing = self.canonical_commit_bytes_for_signing(&commit)?;
        let signature = self.signing_key.sign(&commit_data_for_signing);
        commit.signature = signature.to_bytes().to_base58();
        
        let commit_data_for_hashing = serde_yaml::to_string(&commit)?;
        let id = blake3::hash(commit_data_for_hashing.as_bytes()).to_string();
        commit.id = id.clone();

        self.store_commit(&commit)?;
        self.set_head(&id)?;

        // Print commit summary
        println!("[{}] {}", &id[..8], message);
        println!(" {} file{} changed", 
            changes.added.len() + changes.modified.len() + changes.deleted.len(),
            if (changes.added.len() + changes.modified.len() + changes.deleted.len()) == 1 { "" } else { "s" }
        );
        if !changes.added.is_empty() {
            println!(" [+] {} new file{}", changes.added.len(), if changes.added.len() == 1 { "" } else { "s" });
        }
        if !changes.modified.is_empty() {
            println!(" [~] {} modified file{}", changes.modified.len(), if changes.modified.len() == 1 { "" } else { "s" });
        }
        if !changes.deleted.is_empty() {
            println!(" [-] {} deleted file{}", changes.deleted.len(), if changes.deleted.len() == 1 { "" } else { "s" });
        }

        Ok(id)
    }
    
    fn store_blob(&self, content: &[u8]) -> Result<String> {
        let hash = blake3::hash(content).to_string();
        let dir = self.aegis_dir.join("objects").join(&hash[..2]);
        fs::create_dir_all(&dir)?;
        let blob_path = dir.join(&hash[2..]);
        fs::write(blob_path, content)?;
        Ok(hash)
    }

    fn load_blob(&self, hash: &str) -> Result<Vec<u8>> {
        let blob_path = self.aegis_dir.join("objects").join(&hash[..2]).join(&hash[2..]);
        Ok(fs::read(blob_path)?)
    }

    fn create_tree_from_index(&self, index: &Index) -> Result<String> {
        let tree = Tree {
            entries: index.entries.clone(),
        };
        self.store_tree(&tree)
    }

    fn store_tree(&self, tree: &Tree) -> Result<String> {
        let yaml = serde_yaml::to_string(tree)?;
        let hash = blake3::hash(yaml.as_bytes()).to_string();
        let dir = self.aegis_dir.join("trees").join(&hash[..2]);
        fs::create_dir_all(&dir)?;
        let tree_path = dir.join(&hash[2..]);
        fs::write(tree_path, yaml)?;
        Ok(hash)
    }

    fn load_tree(&self, hash: &str) -> Result<Tree> {
        let tree_path = self.aegis_dir.join("trees").join(&hash[..2]).join(&hash[2..]);
        let yaml = fs::read_to_string(tree_path)?;
        Ok(serde_yaml::from_str(&yaml)?)
    }

    fn store_commit(&self, commit: &Commit) -> Result<()> {
        let dir = self.aegis_dir.join("commits").join(&commit.id[..2]);
        fs::create_dir_all(&dir)?;
        let commit_path = dir.join(&commit.id[2..]);
        let yaml = serde_yaml::to_string(commit)?;
        fs::write(commit_path, yaml)?;
        Ok(())
    }

    fn canonical_commit_bytes_for_signing(&self, commit: &Commit) -> Result<Vec<u8>> {
        let mut map = serde_yaml::Mapping::new();
        map.insert("parents".into(), serde_yaml::to_value(&commit.parents)?);
        map.insert("timestamp".into(), serde_yaml::to_value(&commit.timestamp)?);
        map.insert("author".into(), serde_yaml::to_value(&commit.author)?);
        map.insert("tree_hash".into(), serde_yaml::to_value(&commit.tree_hash)?);
        map.insert("message".into(), serde_yaml::to_value(&commit.message)?);
        map.insert("public_key".into(), serde_yaml::to_value(&commit.public_key)?);
        Ok(serde_yaml::to_string(&map)?.into_bytes())
    }

    fn get_head(&self) -> Result<Option<String>> {
        let head_path = self.aegis_dir.join("HEAD");
        if !head_path.exists() {
            return Ok(None);
        }
        let head = fs::read_to_string(head_path)?;
        Ok(Some(head.trim().to_string()))
    }

    fn set_head(&self, commit_id: &str) -> Result<()> {
        fs::write(self.aegis_dir.join("HEAD"), commit_id)?;
        Ok(())
    }
    
    fn read_index(&self) -> Result<Index> {
        let index_path = self.aegis_dir.join("index");
        let content = fs::read_to_string(index_path)?;
        Ok(serde_yaml::from_str(&content)?)
    }

    fn write_index(&self, index: &Index) -> Result<()> {
        let index_path = self.aegis_dir.join("index");
        let content = serde_yaml::to_string(index)?;
        fs::write(index_path, content)?;
        Ok(())
    }

    fn compute_changes(&self, head: Option<&str>, tree: &Tree) -> Result<Changes> {
        let mut changes = Changes::default();

        if let Some(head) = head {
            let head_commit = self.load_commit(head)?;
            let head_tree = self.load_tree(&head_commit.tree_hash)?;

            for (path, hash) in &head_tree.entries {
                if let Some(new_hash) = tree.entries.get(path) {
                    if new_hash != hash {
                        changes.modified.push(path.clone());
                    }
                } else {
                    changes.deleted.push(path.clone());
                }
            }

            for path in tree.entries.keys() {
                if !head_tree.entries.contains_key(path) {
                    changes.added.push(path.clone());
                }
            }
        } else {
            changes.added = tree.entries.keys().cloned().collect();
        }

        Ok(changes)
    }

    fn status(&self) -> Result<()> {
        let head = self.get_head()?;
        let index = self.read_index()?;

        // Changes to be committed
        let staged_tree = Tree { entries: index.entries.clone() };
        let staged_changes = self.compute_changes(head.as_deref(), &staged_tree)?;
        
        println!("\x1b[1mChanges to be committed:\x1b[0m");
        if staged_changes.added.is_empty() && 
           staged_changes.modified.is_empty() && 
           staged_changes.deleted.is_empty() {
            println!("  (no changes)");
        } else {
            staged_changes.added.iter().for_each(|f| println!("\x1b[32m  new file:   {}\x1b[0m", f));
            staged_changes.modified.iter().for_each(|f| println!("\x1b[33m  modified:   {}\x1b[0m", f));
            staged_changes.deleted.iter().for_each(|f| println!("\x1b[31m  deleted:    {}\x1b[0m", f));
        }
        println!();

        // Changes not staged for commit
        println!("\x1b[1mChanges not staged for commit:\x1b[0m");
        let mut unstaged_modified = Vec::new();
        let mut unstaged_deleted = Vec::new();
        let mut untracked_files = Vec::new();

        for entry in WalkDir::new(&self.path)
            .into_iter()
            .filter_entry(|e| !is_ignored(e.path()))
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
        {
            let relative_path = entry.path().strip_prefix(&self.path)?
                .to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?
                .to_string();
            
            if let Some(staged_hash) = index.entries.get(&relative_path) {
                if !entry.path().exists() {
                    unstaged_deleted.push(relative_path.clone());
                } else {
                    let content = fs::read(entry.path())?;
                    let current_hash = blake3::hash(&content).to_string();
                    if &current_hash != staged_hash {
                        unstaged_modified.push(relative_path);
                    }
                }
            } else {
                untracked_files.push(relative_path);
            }
        }
        
        if unstaged_modified.is_empty() && 
           unstaged_deleted.is_empty() && 
           untracked_files.is_empty() {
            println!("  (no changes)");
        } else {
            unstaged_modified.iter().for_each(|f| println!("\x1b[33m  modified:   {}\x1b[0m", f));
            unstaged_deleted.iter().for_each(|f| println!("\x1b[31m  deleted:    {}\x1b[0m", f));
            untracked_files.iter().for_each(|f| println!("\x1b[31m  untracked:  {}\x1b[0m", f));
        }

        Ok(())
    }

    fn log(&self) -> Result<()> {
        let mut commit_id_opt = self.get_head()?;
        let mut count = 0;
        const MAX_LOG_ENTRIES: usize = 50;
        
        while let Some(id) = commit_id_opt {
            if count >= MAX_LOG_ENTRIES {
                println!("... (showing last {} commits)", MAX_LOG_ENTRIES);
                break;
            }
            
            let commit = self.load_commit(&id)?;
            println!("\x1b[33mcommit {}\x1b[0m", id);
            println!("Author: \x1b[36m{} <{}>\x1b[0m", commit.author.name, commit.author.email);
            println!("Date:   {}", commit.timestamp.format("%Y-%m-%d %H:%M:%S"));
            println!("\n    {}\n", commit.message);
            
            commit_id_opt = commit.parents.get(0).cloned();
            count += 1;
        }
        
        if count == 0 {
            println!("No commits yet");
        }
        
        Ok(())
    }
    
    fn verify(&self, commit_id: &str) -> Result<()> {
        let commit = self.load_commit(commit_id)?;
        
        let public_key_bytes: [u8; 32] = commit.public_key.from_base58()
            .map_err(|_| AegisError::Base58DecodeError)?
            .as_slice()
            .try_into()
            .map_err(|_| AegisError::VerificationFailed)?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;

        let signature_bytes: [u8; 64] = commit.signature.from_base58()
            .map_err(|_| AegisError::Base58DecodeError)?
            .as_slice()
            .try_into()
            .map_err(|_| AegisError::VerificationFailed)?;
        let signature = Signature::from_bytes(&signature_bytes);

        let commit_bytes = self.canonical_commit_bytes_for_signing(&commit)?;
        public_key.verify(&commit_bytes, &signature)?;

        Ok(())
    }

    fn get_public_uid(&self) -> String {
        let hash = blake3::hash(self.signing_key.verifying_key().as_bytes());
        hash.as_bytes()[..8].to_base58()
    }

    fn load_commit(&self, commit_id: &str) -> Result<Commit> {
        let commit_path = self.aegis_dir.join("commits").join(&commit_id[..2]).join(&commit_id[2..]);
        let yaml = match fs::read_to_string(&commit_path) {
            Ok(yaml) => yaml,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(AegisError::InvalidCommit.into());
            }
            Err(e) => return Err(e.into()),
        };
        Ok(serde_yaml::from_str(&yaml)?)
    }
}

fn is_ignored(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy().to_lowercase();
        s == ".aegis" || s == "target" || s == ".git"
    })
}

fn print_help() {
    println!("Aegis VCS - Secure Version Control System");
    println!();
    println!("Usage: aegis <command> [args]");
    println!();
    println!("Commands:");
    println!("  init               Initialize a new repository");
    println!("  add <path>         Add files/directories to staging area");
    println!("  commit <message>   Commit staged changes");
    println!("  status             Show working tree status");
    println!("  log                Show commit history");
    println!("  verify [commit]    Verify commit signatures");
    println!("  help               Show this help message");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_help();
        return Ok(());
    }

    let repo_path = std::env::current_dir()?;

    match args[1].as_str() {
        "init" => {
            Repository::init(&repo_path)?;
            println!("\x1b[32m✓\x1b[0m Initialized empty Aegis repository in {}", repo_path.display());
        }
        "add" => {
            let repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Path required for 'add' command");
            }
            for path in &args[2..] {
                repo.add(path)?;
            }
        }
        "commit" => {
            let repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Commit message required");
            }
            repo.commit(&args[2..].join(" "))?;
        }
        "status" => {
            let repo = Repository::open(&repo_path)?;
            repo.status()?;
        }
        "log" => {
            let repo = Repository::open(&repo_path)?;
            repo.log()?;
        }
        "verify" => {
            let repo = Repository::open(&repo_path)?;
            if let Some(commit_id) = args.get(2) {
                repo.verify(commit_id)?;
                println!("\x1b[32m✓\x1b[0m Commit {} verified successfully", commit_id);
            } else {
                let mut commit_id_opt = repo.get_head()?;
                while let Some(id) = commit_id_opt {
                    repo.verify(&id)?;
                    println!("\x1b[32m✓\x1b[0m Verified commit {}", id);
                    let commit = repo.load_commit(&id)?;
                    commit_id_opt = commit.parents.get(0).cloned();
                }
            }
        }
        "help" | "--help" | "-h" => {
            print_help();
        }
        _ => {
            println!("Unknown command: {}", args[1]);
            print_help();
        }
    }

    Ok(())
}
