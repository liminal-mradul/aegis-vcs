use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Result};
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
    #[error("Branch not found: {0}")]
    BranchNotFound(String),
    #[error("Conflict detected in {0}")]
    Conflict(String),
    #[error("Hook failed: {0}")]
    HookFailed(String),
    #[error("Invalid ignore pattern: {0}")]
    InvalidIgnorePattern(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Author {
    name: String,
    email: String,
    uid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)] // Added Clone
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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Branch {
    name: String,
    commit_id: String,
    signature: String,
    timestamp: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Tag {
    name: String,
    commit_id: String,
    message: String,
    signature: String,
    timestamp: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Stash {
    id: String,
    tree_hash: String,
    message: String,
    branch: String,
    timestamp: DateTime<Utc>,
    signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RefLogEntry {
    timestamp: DateTime<Utc>,
    old_commit: String,
    new_commit: String,
    command: String,
    message: String,
    signature: String,
}

struct Repository {
    path: PathBuf,
    aegis_dir: PathBuf,
    signing_key: SigningKey,
    current_branch: String,
    config: Config,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    hash_algorithm: String,
    signature_algorithm: String,
    uid_length: usize,
    ignore_patterns: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hash_algorithm: "blake3".to_string(),
            signature_algorithm: "ed25519".to_string(),
            uid_length: 12,
            ignore_patterns: vec![
                ".aegis".to_string(),
                "target".to_string(),
                ".git".to_string(),
            ],
        }
    }
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
        fs::create_dir_all(aegis_dir.join("branches"))?;
        fs::create_dir_all(aegis_dir.join("tags"))?;
        fs::create_dir_all(aegis_dir.join("stashes"))?;
        fs::create_dir_all(aegis_dir.join("hooks"))?;
        fs::create_dir_all(aegis_dir.join("reflog"))?;

        let signing_key = SigningKey::generate(&mut OsRng);
        let keypair_bytes = signing_key.to_keypair_bytes();
        fs::write(aegis_dir.join("keypair.bin"), &keypair_bytes)?;

        let index = Index::default();
        let index_bytes = serde_yaml::to_string(&index)?;
        fs::write(aegis_dir.join("index"), index_bytes)?;

        let config = Config::default();
        let config_yaml = serde_yaml::to_string(&config)?;
        fs::write(aegis_dir.join("config.yaml"), config_yaml)?;

        // Create initial branch
        let initial_branch = "main".to_string();
        
        fs::write(aegis_dir.join("current_branch"), &initial_branch)?;

        // Create default ignore file
        fs::write(path.join(".aegisignore"), "/target\n/.aegis\n/.git\n")?;

        let mut repo = Self {
            path: path.to_path_buf(),
            aegis_dir: aegis_dir.clone(),
            signing_key,
            current_branch: initial_branch.clone(),
            config,
        };

        // Create initial branch reference
        repo.create_branch(&initial_branch, None)?;

        Ok(repo)
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

        let config_yaml = fs::read_to_string(aegis_dir.join("config.yaml"))?;
        let config: Config = serde_yaml::from_str(&config_yaml)?;

        let current_branch = fs::read_to_string(aegis_dir.join("current_branch"))?;

        Ok(Self {
            path: path.to_path_buf(),
            aegis_dir: aegis_dir.clone(),
            signing_key,
            current_branch: current_branch.trim().to_string(),
            config,
        })
    }

    // ========================
    // CORE VCS FUNCTIONALITY
    // ========================

    fn add(&mut self, path_to_add: &str) -> Result<()> {
        if self.run_hook("pre-add").is_err() {
            return Err(AegisError::HookFailed("pre-add".to_string()).into());
        }

        let mut index = self.read_index()?;
        let file_path = self.path.join(path_to_add);

        if !file_path.exists() {
            if index.entries.remove(path_to_add).is_some() {
                println!("Removed: {}", path_to_add);
            } else {
                return Err(AegisError::PathNotFound(path_to_add.to_string()).into());
            }
        } else if file_path.is_file() {
            if self.is_ignored(&file_path) {
                println!("Ignored: {}", path_to_add);
                return Ok(());
            }
            let content = fs::read(&file_path)?;
            let hash = self.store_blob(&content)?;
            index.entries.insert(path_to_add.to_string(), hash);
            println!("Staged: {}", path_to_add);
        } else if file_path.is_dir() {
            for entry in WalkDir::new(&file_path)
                .into_iter()
                .filter_entry(|e| !self.is_ignored(e.path()))
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
            {
                let relative_path = entry.path().strip_prefix(&self.path)?.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?.to_string();
                if self.is_ignored(entry.path()) {
                    continue;
                }
                let content = fs::read(entry.path())?;
                let hash = self.store_blob(&content)?;
                index.entries.insert(relative_path.clone(), hash);
                println!("Staged: {}", relative_path);
            }
        }
        self.write_index(&index)?;

        if self.run_hook("post-add").is_err() {
            return Err(AegisError::HookFailed("post-add".to_string()).into());
        }

        Ok(())
    }

    fn commit(&mut self, message: &str) -> Result<String> {
        if self.run_hook("pre-commit").is_err() {
            return Err(AegisError::HookFailed("pre-commit".to_string()).into());
        }

        let head = self.get_head_commit()?;
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
            parents: head.clone().map_or_else(|| vec![], |h| vec![h]),
            timestamp,
            author: author.clone(),
            tree_hash: tree_hash.clone(),
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
        self.update_branch(&self.current_branch, &id)?;
        self.add_reflog_entry(
            &head.as_ref().map(|s| s.as_str()).unwrap_or(""),
            &id,
            "commit",
            message,
        )?;

        // Print commit summary
        println!("\x1b[32m[{}] {}\x1b[0m", &id[..8], message);
        println!(" {} file{} changed", 
            changes.added.len() + changes.modified.len() + changes.deleted.len(),
            if (changes.added.len() + changes.modified.len() + changes.deleted.len()) == 1 { "" } else { "s" }
        );
        if !changes.added.is_empty() {
            println!(" \x1b[32m[+]\x1b[0m {} new file{}", changes.added.len(), if changes.added.len() == 1 { "" } else { "s" });
        }
        if !changes.modified.is_empty() {
            println!(" \x1b[33m[~]\x1b[0m {} modified file{}", changes.modified.len(), if changes.modified.len() == 1 { "" } else { "s" });
        }
        if !changes.deleted.is_empty() {
            println!(" \x1b[31m[-]\x1b[0m {} deleted file{}", changes.deleted.len(), if changes.deleted.len() == 1 { "" } else { "s" });
        }

        if self.run_hook("post-commit").is_err() {
            return Err(AegisError::HookFailed("post-commit".to_string()).into());
        }

        Ok(id)
    }

    fn status(&self) -> Result<()> {
        let head = self.get_head_commit()?;
        let index = self.read_index()?;

        println!("\x1b[1;34mOn branch {}\x1b[0m", self.current_branch);
        println!();

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
            .filter_entry(|e| !self.is_ignored(e.path()))
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
            } else if !self.is_ignored(entry.path()) {
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
        let mut commit_id_opt = self.get_head_commit()?;
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

        println!("\x1b[32m✓\x1b[0m Commit {} verified successfully", commit_id);
        Ok(())
    }

    // ========================
    // BRANCHING SYSTEM
    // ========================

    fn create_branch(&mut self, name: &str, start_point: Option<&str>) -> Result<()> {
        let commit_id = match start_point {
            Some(id) => id.to_string(),
            None => self.get_head_commit()?.unwrap_or_default(),
        };

        if self.branch_exists(name) {
            anyhow::bail!("Branch '{}' already exists", name);
        }

        let branch = Branch {
            name: name.to_string(),
            commit_id: commit_id.clone(),
            signature: self.sign(&format!("{}{}", name, commit_id))?,
            timestamp: Utc::now(),
        };

        self.store_branch(&branch)?;
        if commit_id.is_empty() {
            println!("Created branch '{}' (no commits yet)", name);
        } else {
            // This part is now safe because we know commit_id is not empty.
            println!("Created branch '{}' at {}", name, &commit_id[..8]);
        }
        Ok(())
    }

    fn list_branches(&self) -> Result<Vec<String>> {
        let mut branches = Vec::new();
        let branches_dir = self.aegis_dir.join("branches");
        
        for entry in fs::read_dir(branches_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    branches.push(name.to_string());
                }
            }
        }
        
        Ok(branches)
    }

    fn checkout(&mut self, target: &str) -> Result<()> {
        if self.run_hook("pre-checkout").is_err() {
            return Err(AegisError::HookFailed("pre-checkout".to_string()).into());
        }

        // Check if target is a branch
        if self.branch_exists(target) {
            let branch = self.load_branch(target)?;
            self.current_branch = target.to_string();
            fs::write(self.aegis_dir.join("current_branch"), target)?;
            self.set_head(&branch.commit_id)?;
            println!("Switched to branch '{}'", target);
            self.add_reflog_entry(
                &self.get_head_commit()?.unwrap_or_default(),
                &branch.commit_id,
                "checkout",
                &format!("branch: {}", target),
            )?;
            return Ok(());
        }

        // Check if target is a commit
        if self.commit_exists(target) {
            self.set_head(target)?;
            println!("HEAD is now at {}", &target[..8]);
            self.add_reflog_entry(
                &self.get_head_commit()?.unwrap_or_default(),
                target,
                "checkout",
                "detached HEAD",
            )?;
            return Ok(());
        }

        Err(AegisError::BranchNotFound(target.to_string()).into())
    }

    fn merge(&mut self, source_branch: &str) -> Result<()> {
        if self.run_hook("pre-merge").is_err() {
            return Err(AegisError::HookFailed("pre-merge".to_string()).into());
        }

        let current_commit = self.get_head_commit()?
            .ok_or_else(|| anyhow::anyhow!("No current commit"))?;
        let source_branch = self.load_branch(source_branch)?;
        let _source_commit = self.load_commit(&source_branch.commit_id)?;

        // Find common ancestor
        let ancestor = self.find_common_ancestor(&current_commit, &source_branch.commit_id)?;

        // Check for conflicts
        let conflicts = self.detect_conflicts(&current_commit, &source_branch.commit_id, &ancestor)?;
        if !conflicts.is_empty() {
            for conflict in &conflicts {
                println!("\x1b[31mCONFLICT: {}\x1b[0m", conflict);
                self.write_conflict_marker(conflict)?;
            }
            return Err(AegisError::Conflict("Merge conflicts detected".to_string()).into());
        }

        // Create merge commit
        let message = format!("Merge branch '{}' into {}", source_branch.name, self.current_branch);
        let index = self.read_index()?;
        let tree_hash = self.create_tree_from_index(&index)?;

        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "localhost".to_string());
        let username = whoami::username();

        let author = Author {
            name: whoami::realname(),
            email: format!("{}@{}", username, hostname),
            uid: self.get_public_uid(),
        };

        let mut commit = Commit {
            id: String::new(),
            parents: vec![current_commit.clone(), source_branch.commit_id.clone()],
            timestamp: Utc::now(),
            author: author.clone(),
            tree_hash: tree_hash.clone(),
            changes: Changes::default(),
            message: message.clone(),
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
        self.update_branch(&self.current_branch, &id)?;
        self.add_reflog_entry(
            &current_commit,
            &id,
            "merge",
            &format!("{} into {}", source_branch.name, self.current_branch),
        )?;

        println!("Merge commit {} created", &id[..8]);

        if self.run_hook("post-merge").is_err() {
            return Err(AegisError::HookFailed("post-merge".to_string()).into());
        }

        Ok(())
    }

    // ========================
    // TAGGING SYSTEM
    // ========================

    fn create_tag(&self, name: &str, message: &str) -> Result<()> {
        let commit_id = self.get_head_commit()?
            .ok_or_else(|| anyhow::anyhow!("No current commit"))?;

        if self.tag_exists(name) {
            anyhow::bail!("Tag '{}' already exists", name);
        }

        let tag = Tag {
            name: name.to_string(),
            commit_id: commit_id.clone(),
            message: message.to_string(),
            signature: self.sign(&format!("{}{}{}", name, commit_id, message))?,
            timestamp: Utc::now(),
        };

        self.store_tag(&tag)?;
        println!("Created tag '{}' at {}", name, &commit_id[..8]);
        Ok(())
    }

    fn list_tags(&self) -> Result<Vec<String>> {
        let mut tags = Vec::new();
        let tags_dir = self.aegis_dir.join("tags");
        
        for entry in fs::read_dir(tags_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    tags.push(name.to_string());
                }
            }
        }
        
        Ok(tags)
    }

    // ========================
    // STASHING SYSTEM
    // ========================

    fn stash(&mut self, message: &str) -> Result<()> {
        if self.run_hook("pre-stash").is_err() {
            return Err(AegisError::HookFailed("pre-stash".to_string()).into());
        }

        let index = self.read_index()?;
        let tree_hash = self.create_tree_from_index(&index)?;
        
        let stash = Stash {
            id: blake3::hash(message.as_bytes()).to_string(),
            tree_hash,
            message: message.to_string(),
            branch: self.current_branch.clone(),
            timestamp: Utc::now(),
            signature: self.sign(&format!("{}{}", message, self.current_branch))?,
        };

        self.store_stash(&stash)?;
        println!("Stashed changes: {}", message);

        // Reset to HEAD
        if let Some(head) = self.get_head_commit()? {
            self.reset_hard(&head)?;
        }

        if self.run_hook("post-stash").is_err() {
            return Err(AegisError::HookFailed("post-stash".to_string()).into());
        }

        Ok(())
    }

    fn stash_apply(&mut self, stash_id: Option<&str>) -> Result<()> {
        if self.run_hook("pre-stash-apply").is_err() {
            return Err(AegisError::HookFailed("pre-stash-apply".to_string()).into());
        }

        let stash = match stash_id {
            Some(id) => self.load_stash(id)?,
            None => self.load_latest_stash()?,
        };

        let stash_tree = self.load_tree(&stash.tree_hash)?;
        let current_tree = self.get_head_tree()?;
        let conflicts = self.detect_tree_conflicts(&current_tree, &stash_tree)?;

        if !conflicts.is_empty() {
            for conflict in &conflicts {
                println!("\x1b[31mCONFLICT: {}\x1b[0m", conflict);
            }
            return Err(AegisError::Conflict("Stash application conflicts".to_string()).into());
        }

        // Apply changes
        self.apply_tree(&stash_tree)?;
        println!("Applied stash: {}", stash.message);

        if self.run_hook("post-stash-apply").is_err() {
            return Err(AegisError::HookFailed("post-stash-apply".to_string()).into());
        }

        Ok(())
    }

    // ========================
    // ADVANCED HISTORY
    // ========================

    fn reflog(&self) -> Result<()> {
        let reflog_path = self.aegis_dir.join("reflog").join("HEAD.log");
        if !reflog_path.exists() {
            println!("No reflog entries");
            return Ok(());
        }

        let entries: Vec<RefLogEntry> = serde_yaml::from_reader(io::BufReader::new(fs::File::open(reflog_path)?))?;
        
        println!("Reflog for HEAD:");
        for entry in entries.iter().rev().take(50) {
            println!(
                "{} {}: {} -> {} | {}",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                entry.command,
                &entry.old_commit[..8],
                &entry.new_commit[..8],
                entry.message
            );
        }
        
        Ok(())
    }

    fn blame(&self, file_path: &str) -> Result<()> {
        let current_content = fs::read_to_string(self.path.join(file_path))?;
        let mut current_lines = current_content.lines().collect::<Vec<_>>();
        
        let mut commit_history = Vec::new();
        let mut commit_id_opt = self.get_head_commit()?;
        
        while let Some(id) = commit_id_opt {
            let commit = self.load_commit(&id)?;
            // Save next commit ID before moving commit
            commit_id_opt = commit.parents.get(0).cloned();
            
            if commit.changes.added.contains(&file_path.to_string()) || 
               commit.changes.modified.contains(&file_path.to_string()) {
                commit_history.push(commit);
            }
        }
        
        commit_history.reverse();
        
        for commit in commit_history {
            let tree = self.load_tree(&commit.tree_hash)?;
            if let Some(blob_hash) = tree.entries.get(file_path) {
                let blob_content = self.load_blob(blob_hash)?;
                let blob_str = String::from_utf8_lossy(&blob_content);
                let blob_lines = blob_str.lines().collect::<Vec<_>>();
                
                for (i, line) in blob_lines.iter().enumerate() {
                    if i < current_lines.len() && current_lines[i] == *line {
                        println!(
                            "\x1b[33m{} \x1b[36m{} \x1b[0m{}",
                            &commit.id[..8],
                            commit.author.name,
                            line
                        );
                        current_lines.remove(i);
                    }
                }
            }
        }
        
        // Remaining lines (new or modified)
        for line in current_lines {
            println!("\x1b[33mUNCOMMITTED \x1b[36mCURRENT \x1b[0m{}", line);
        }
        
        Ok(())
    }

    // ========================
    // REVERSIBLE OPERATIONS
    // ========================

    fn revert(&mut self, commit_id: &str) -> Result<()> {
        let commit_to_revert = self.load_commit(commit_id)?;
        let current_tree = self.get_head_tree()?;
        let revert_tree = self.load_tree(&commit_to_revert.tree_hash)?;
        
        let conflicts = self.detect_tree_conflicts(&current_tree, &revert_tree)?;
        if !conflicts.is_empty() {
            for conflict in &conflicts {
                println!("\x1b[31mCONFLICT: {}\x1b[0m", conflict);
            }
            return Err(AegisError::Conflict("Revert conflicts detected".to_string()).into());
        }
        
        // Create inverse changes
        let mut changes = Changes::default();
        for (path, _) in &revert_tree.entries {
            if current_tree.entries.contains_key(path) {
                changes.modified.push(path.clone());
            } else {
                changes.added.push(path.clone());
            }
        }
        
        for path in current_tree.entries.keys() {
            if !revert_tree.entries.contains_key(path) {
                changes.deleted.push(path.clone());
            }
        }
        
        // Create revert commit
        let message = format!("Revert \"{}\"", commit_to_revert.message);
        let index = self.read_index()?;
        let tree_hash = self.create_tree_from_index(&index)?;

        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "localhost".to_string());
        let username = whoami::username();

        let author = Author {
            name: whoami::realname(),
            email: format!("{}@{}", username, hostname),
            uid: self.get_public_uid(),
        };

        let head_commit = self.get_head_commit()?.unwrap_or_default();
        
        let mut commit = Commit {
            id: String::new(),
            parents: vec![head_commit.clone()],
            timestamp: Utc::now(),
            author: author.clone(),
            tree_hash: tree_hash.clone(),
            changes: changes.clone(),
            message: message.clone(),
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
        self.update_branch(&self.current_branch, &id)?;
        self.add_reflog_entry(
            &head_commit,
            &id,
            "revert",
            &format!("Reverted commit {}", commit_id),
        )?;

        println!("Reverted commit {} as {}", commit_id, &id[..8]);
        Ok(())
    }

    fn reset_hard(&mut self, commit_id: &str) -> Result<()> {
        let commit = self.load_commit(commit_id)?;
        let tree = self.load_tree(&commit.tree_hash)?;
        
        // Remove all files not in the target tree
        for path in self.list_all_tracked_files()? {
            if !tree.entries.contains_key(&path) {
                let abs_path = self.path.join(&path);
                if abs_path.exists() {
                    fs::remove_file(&abs_path)?;
                }Trust and Peer-to-Peer Communication
            }
        }
        
        // Restore files from target tree
        for (path, hash) in &tree.entries {
            let abs_path = self.path.join(path);
            let content = self.load_blob(hash)?;
            if let Some(parent) = abs_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&abs_path, content)?;
        }
        
        // Update index
        let mut index = Index::default();
        index.entries = tree.entries.clone();
        self.write_index(&index)?;
        
        // Update HEAD
        self.set_head(commit_id)?;
        
        println!("Reset to commit {}", &commit_id[..8]);
        Ok(())
    }

    // ========================
    // PARTIAL STAGING
    // ========================

    fn add_patch(&mut self, path: &str) -> Result<()> {
        let file_path = self.path.join(path);
        if !file_path.exists() || !file_path.is_file() {
            return Err(AegisError::PathNotFound(path.to_string()).into());
        }
        
        let current_content = fs::read_to_string(&file_path)?;
        let index_content = if let Some(hash) = self.read_index()?.entries.get(path) {
            String::from_utf8_lossy(&self.load_blob(hash)?).to_string()
        } else {
            "".to_string()
        };
        
        let diff = diffy::create_patch(&index_content, &current_content);
        let hunks = diff.hunks(); // Directly use the slice
        
        if hunks.is_empty() {
            println!("No changes to {}", path);
            return Ok(());
        }
        
        println!("Select changes to stage for {}:", path);
    for (i, hunk) in hunks.iter().enumerate() {
        println!("\nHunk {}:", i + 1);
        println!("{:?}", hunk);
        }
        
        println!("\nStage hunks? [y,n,q,a,d,?] ");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        match input.trim() {
            "y" => self.add(path)?,
            "a" => self.add(path)?,
            "d" => {}, // Skip
            "q" => return Ok(()),
            _ => println!("Invalid selection"),
        }
        
        Ok(())
    }

    // ========================
    // IGNORE SYSTEM
    // ========================

    fn add_ignore_pattern(&mut self, pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(AegisError::InvalidIgnorePattern("Empty pattern".to_string()).into());
        }
        
        self.config.ignore_patterns.push(pattern.to_string());
        let config_yaml = serde_yaml::to_string(&self.config)?;
        fs::write(self.aegis_dir.join("config.yaml"), config_yaml)?;
        
        // Update .aegisignore file
        let ignore_path = self.path.join(".aegisignore");
        let mut contents = if ignore_path.exists() {
            fs::read_to_string(&ignore_path)?
        } else {
            String::new()
        };
        
        if !contents.contains(pattern) {
            contents.push_str(pattern);
            contents.push('\n');
            fs::write(ignore_path, contents)?;
        }
        
        println!("Added ignore pattern: {}", pattern);
        Ok(())
    }

    // ========================
    // HOOKS SYSTEM
    // ========================

    fn run_hook(&self, hook_name: &str) -> Result<()> {
        let hook_path = self.aegis_dir.join("hooks").join(hook_name);
        if !hook_path.exists() {
            return Ok(());
        }
        
        if !hook_path.is_file() {
            return Err(anyhow!("Hook {} is not a file", hook_name));
        }
        
        let status = Command::new(hook_path)
            .current_dir(&self.path)
            .status()?;
        
        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("Hook {} failed with exit code: {:?}", hook_name, status.code()))
        }
    }

    // ========================
    // INTERNAL HELPERS
    // ========================

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

    fn get_head_commit(&self) -> Result<Option<String>> {
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
    
    fn get_public_uid(&self) -> String {
        let hash = blake3::hash(self.signing_key.verifying_key().as_bytes());
        hash.as_bytes()[..8].to_base58()
    }

    fn load_commit(&self, commit_id: &str) -> Result<Commit> {
        if commit_id.len() < 64 {
            return Err(AegisError::InvalidCommit.into());
        }
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
    
    fn commit_exists(&self, commit_id: &str) -> bool {
        self.aegis_dir.join("commits").join(&commit_id[..2]).join(&commit_id[2..]).exists()
    }

    fn is_ignored(&self, path: &Path) -> bool {
        let relative_path = path.strip_prefix(&self.path).unwrap_or(path);
        let path_str = relative_path.to_string_lossy().to_string();
        
        for pattern in &self.config.ignore_patterns {
            if glob_match::glob_match(pattern, &path_str) {
                return true;
            }
        }
        
        false
    }
    
    fn sign(&self, data: &str) -> Result<String> {
        let signature = self.signing_key.sign(data.as_bytes());
        Ok(signature.to_bytes().to_base58())
    }
    
    fn verify_signature(&self, data: &str, signature: &str, public_key: &str) -> Result<()> {
        let public_key_bytes: [u8; 32] = public_key.from_base58()
            .map_err(|_| AegisError::Base58DecodeError)?
            .as_slice()
            .try_into()
            .map_err(|_| AegisError::VerificationFailed)?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;

        let signature_bytes: [u8; 64] = signature.from_base58()
            .map_err(|_| AegisError::Base58DecodeError)?
            .as_slice()
            .try_into()
            .map_err(|_| AegisError::VerificationFailed)?;
        let signature = Signature::from_bytes(&signature_bytes);

        public_key.verify(data.as_bytes(), &signature)?;
        Ok(())
    }
    
    fn branch_exists(&self, name: &str) -> bool {
        self.aegis_dir.join("branches").join(format!("{}.yaml", name)).exists()
    }
    
    fn store_branch(&self, branch: &Branch) -> Result<()> {
        let yaml = serde_yaml::to_string(branch)?;
        fs::write(self.aegis_dir.join("branches").join(format!("{}.yaml", branch.name)), yaml)?;
        Ok(())
    }
    
    fn load_branch(&self, name: &str) -> Result<Branch> {
        let branch_path = self.aegis_dir.join("branches").join(format!("{}.yaml", name));
        let yaml = fs::read_to_string(branch_path)?;
        let branch: Branch = serde_yaml::from_str(&yaml)?;
        
        // Verify signature
        self.verify_signature(
            &format!("{}{}", branch.name, branch.commit_id),
            &branch.signature,
            &self.signing_key.verifying_key().to_bytes().to_base58(),
        )?;
        
        Ok(branch)
    }
    
    fn update_branch(&self, name: &str, commit_id: &str) -> Result<()> {
        let mut branch = self.load_branch(name)?;
        branch.commit_id = commit_id.to_string();
        branch.signature = self.sign(&format!("{}{}", name, commit_id))?;
        branch.timestamp = Utc::now();
        self.store_branch(&branch)?;
        Ok(())
    }
    
    fn tag_exists(&self, name: &str) -> bool {
        self.aegis_dir.join("tags").join(format!("{}.yaml", name)).exists()
    }
    
    fn store_tag(&self, tag: &Tag) -> Result<()> {
        let yaml = serde_yaml::to_string(tag)?;
        fs::write(self.aegis_dir.join("tags").join(format!("{}.yaml", tag.name)), yaml)?;
        Ok(())
    }
    
    fn load_tag(&self, name: &str) -> Result<Tag> {
        let tag_path = self.aegis_dir.join("tags").join(format!("{}.yaml", name));
        let yaml = fs::read_to_string(tag_path)?;
        let tag: Tag = serde_yaml::from_str(&yaml)?;
        
        // Verify signature
        self.verify_signature(
            &format!("{}{}{}", tag.name, tag.commit_id, tag.message),
            &tag.signature,
            &self.signing_key.verifying_key().to_bytes().to_base58(),
        )?;
        
        Ok(tag)
    }
    
    fn store_stash(&self, stash: &Stash) -> Result<()> {
        let yaml = serde_yaml::to_string(stash)?;
        fs::write(self.aegis_dir.join("stashes").join(format!("{}.yaml", stash.id)), yaml)?;
        Ok(())
    }
    
    fn load_stash(&self, stash_id: &str) -> Result<Stash> {
        let stash_path = self.aegis_dir.join("stashes").join(format!("{}.yaml", stash_id));
        let yaml = fs::read_to_string(stash_path)?;
        let stash: Stash = serde_yaml::from_str(&yaml)?;
        
        // Verify signature
        self.verify_signature(
            &format!("{}{}", stash.message, stash.branch),
            &stash.signature,
            &self.signing_key.verifying_key().to_bytes().to_base58(),
        )?;
        
        Ok(stash)
    }
    
    fn load_latest_stash(&self) -> Result<Stash> {
        let mut latest_stash: Option<Stash> = None;
        
        for entry in fs::read_dir(self.aegis_dir.join("stashes"))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "yaml").unwrap_or(false) {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let stash = self.load_stash(stem)?;
                    if latest_stash.as_ref().map(|s| s.timestamp < stash.timestamp).unwrap_or(true) {
                        latest_stash = Some(stash);
                    }
                }
            }
        }
        
        latest_stash.ok_or_else(|| anyhow::anyhow!("No stashes found"))
    }
    
    fn add_reflog_entry(&self, old_commit: &str, new_commit: &str, command: &str, message: &str) -> Result<()> {
        let entry = RefLogEntry {
            timestamp: Utc::now(),
            old_commit: old_commit.to_string(),
            new_commit: new_commit.to_string(),
            command: command.to_string(),
            message: message.to_string(),
            signature: self.sign(&format!("{}{}{}{}", old_commit, new_commit, command, message))?,
        };
        
        let reflog_path = self.aegis_dir.join("reflog").join("HEAD.log");
        let mut entries = if reflog_path.exists() {
            let file = fs::File::open(&reflog_path)?;
            serde_yaml::from_reader(io::BufReader::new(file))?
        } else {
            Vec::new()
        };
        
        entries.push(entry);
        let yaml = serde_yaml::to_string(&entries)?;
        fs::write(reflog_path, yaml)?;
        
        Ok(())
    }
    
    fn find_common_ancestor(&self, commit1: &str, commit2: &str) -> Result<String> {
        let mut history1 = HashSet::new();
        let mut current = commit1.to_string();
        
        while self.commit_exists(&current) {
            history1.insert(current.clone());
            let commit = self.load_commit(&current)?;
            current = commit.parents.get(0).cloned().unwrap_or_default();
            if current.is_empty() {
                break;
            }
        }
        
        let mut current = commit2.to_string();
        while self.commit_exists(&current) {
            if history1.contains(&current) {
                return Ok(current);
            }
            let commit = self.load_commit(&current)?;
            current = commit.parents.get(0).cloned().unwrap_or_default();
            if current.is_empty() {
                break;
            }
        }
        
        Err(anyhow!("No common ancestor found"))
    }
    
    fn detect_conflicts(&self, commit1: &str, commit2: &str, ancestor: &str) -> Result<Vec<String>> {
        let tree1 = self.get_commit_tree(commit1)?;
        let tree2 = self.get_commit_tree(commit2)?;
        let base_tree = self.get_commit_tree(ancestor)?;
        
        let mut conflicts = Vec::new();
        
        for (path, hash1) in &tree1.entries {
            if let Some(hash2) = tree2.entries.get(path) {
                if hash1 != hash2 {
                    if let Some(base_hash) = base_tree.entries.get(path) {
                        if base_hash != hash1 && base_hash != hash2 {
                            conflicts.push(path.clone());
                        }
                    } else {
                        conflicts.push(path.clone());
                    }
                }
            }
        }
        
        for path in tree2.entries.keys() {
            if !tree1.entries.contains_key(path) {
                if base_tree.entries.contains_key(path) {
                    conflicts.push(path.clone());
                }
            }
        }
        
        Ok(conflicts)
    }
    
    fn get_commit_tree(&self, commit_id: &str) -> Result<Tree> {
        let commit = self.load_commit(commit_id)?;
        self.load_tree(&commit.tree_hash)
    }
    
    fn get_head_tree(&self) -> Result<Tree> {
        if let Some(head) = self.get_head_commit()? {
            self.get_commit_tree(&head)
        } else {
            Ok(Tree { entries: BTreeMap::new() })
        }
    }
    
    fn write_conflict_marker(&self, path: &str) -> Result<()> {
        let file_path = self.path.join(path);
        if file_path.exists() {
            let content = fs::read_to_string(&file_path)?;
            let conflict_content = format!(
                "{}\n<<<<<<< HEAD\n=======\n>>>>>>> incoming\n",
                content
            );
            fs::write(file_path, conflict_content)?;
        }
        Ok(())
    }
    
    fn detect_tree_conflicts(&self, current_tree: &Tree, target_tree: &Tree) -> Result<Vec<String>> {
        let mut conflicts = Vec::new();
        
        for (path, current_hash) in &current_tree.entries {
            if let Some(target_hash) = target_tree.entries.get(path) {
                if current_hash != target_hash {
                    conflicts.push(path.clone());
                }
            }
        }
        
        for path in target_tree.entries.keys() {
            if !current_tree.entries.contains_key(path) {
                conflicts.push(path.clone());
            }
        }
        
        Ok(conflicts)
    }
    
    fn apply_tree(&self, tree: &Tree) -> Result<()> {
        let mut index = self.read_index()?;
        
        for (path, hash) in &tree.entries {
            let abs_path = self.path.join(path);
            if let Some(parent) = abs_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let content = self.load_blob(hash)?;
            fs::write(&abs_path, content)?;
            index.entries.insert(path.clone(), hash.clone());
        }
        
        self.write_index(&index)?;
        Ok(())
    }
    
    fn list_all_tracked_files(&self) -> Result<Vec<String>> {
        let index = self.read_index()?;
        Ok(index.entries.keys().cloned().collect())
    }
}

fn print_help() {
    println!("Aegis VCS - Secure Version Control System");
    println!();
    println!("Usage: aegis <command> [args]");
    println!();
    println!("Core Commands:");
    println!("  init               Initialize a new repository");
    println!("  add <path>         Add files/directories to staging area");
    println!("  commit <message>   Commit staged changes");
    println!("  status             Show working tree status");
    println!("  log                Show commit history");
    println!("  verify [commit]    Verify commit signatures");
    println!();
    println!("Branching & Merging:");
    println!("  branch [name]      List or create branches");
    println!("  checkout <target>  Switch branches or commits");
    println!("  merge <branch>     Merge another branch into current");
    println!();
    println!("Tagging:");
    println!("  tag <name> [msg]   Create a new tag");
    println!("  tag -l             List existing tags");
    println!();
    println!("Stashing:");
    println!("  stash [message]    Stash changes");
    println!("  stash apply        Apply latest stash");
    println!();
    println!("History & Inspection:");
    println!("  reflog             Show reference log");
    println!("  blame <file>       Show line-by-line revision information");
    println!();
    println!("Undo Operations:");
    println!("  revert <commit>    Revert a commit");
    println!("  reset <commit>     Reset current HEAD to a commit (hard)");
    println!();
    println!("Advanced:");
    println!("  add -p [path]      Interactive partial staging");
    println!("  ignore <pattern>   Add ignore pattern");
    println!();
    println!("Help:");
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
            Ok(())
        }
        "add" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Path required for 'add' command");
            }
            
            if args[2] == "-p" {
                if args.len() < 4 {
                    anyhow::bail!("Path required for 'add -p' command");
                }
                repo.add_patch(&args[3])
            } else {
                for path in &args[2..] {
                    repo.add(path)?;
                }
                Ok(())
            }
        }
        "commit" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Commit message required");
            }
            repo.commit(&args[2..].join(" "))?;
            Ok(())
        }
        "status" => {
            let repo = Repository::open(&repo_path)?;
            repo.status()
        }
        "log" => {
            let repo = Repository::open(&repo_path)?;
            repo.log()
        }
        "verify" => {
            let repo = Repository::open(&repo_path)?;
            if let Some(commit_id) = args.get(2) {
                repo.verify(commit_id)
            } else {
                let mut commit_id_opt = repo.get_head_commit()?;
                while let Some(id) = commit_id_opt {
                    repo.verify(&id)?;
                    let commit = repo.load_commit(&id)?;
                    commit_id_opt = commit.parents.get(0).cloned();
                }
                Ok(())
            }
        }
        "branch" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() > 2 {
                repo.create_branch(&args[2], None)
            } else {
                let branches = repo.list_branches()?;
                println!("Branches:");
                for branch in branches {
                    if branch == repo.current_branch {
                        println!("* \x1b[32m{}\x1b[0m", branch);
                    } else {
                        println!("  {}", branch);
                    }
                }
                Ok(())
            }
        }
        "checkout" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Target required for checkout");
            }
            repo.checkout(&args[2])
        }
        "merge" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Branch required for merge");
            }
            repo.merge(&args[2])
        }
        "tag" => {
            let repo = Repository::open(&repo_path)?;
            if args.len() > 2 {
                let message = if args.len() > 3 { args[3..].join(" ") } else { "".to_string() };
                repo.create_tag(&args[2], &message)
            } else {
                let tags = repo.list_tags()?;
                println!("Tags:");
                for tag in tags {
                    println!("  {}", tag);
                }
                Ok(())
            }
        }
        "stash" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() > 2 && args[2] == "apply" {
                let stash_id = args.get(3).map(|s| s.as_str());
                repo.stash_apply(stash_id)?;
                Ok(())
            } else {
                let message = if args.len() > 2 { args[2..].join(" ") } else { "Stash".to_string() };
                repo.stash(&message)?;
                Ok(())
            }
        }
        "reflog" => {
            let repo = Repository::open(&repo_path)?;
            repo.reflog()
        }
        "blame" => {
            let repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("File required for blame");
            }
            repo.blame(&args[2])
        }
        "revert" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Commit required for revert");
            }
            repo.revert(&args[2])
        }
        "reset" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Commit required for reset");
            }
            repo.reset_hard(&args[2])
        }
        "ignore" => {
            let mut repo = Repository::open(&repo_path)?;
            if args.len() < 3 {
                anyhow::bail!("Pattern required for ignore");
            }
            repo.add_ignore_pattern(&args[2])
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => {
            println!("Unknown command: {}", args[1]);
            print_help();
            Ok(())
        }
    }
}
