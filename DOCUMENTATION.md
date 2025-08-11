
# AegisVCS<sub>local</sub> — Secure Version Control System 

> A cryptographically secure repository & signed-commit system written in Rust.

---

## Overview

Aegis is a minimal yet fully typed implementation of a cryptographically-backed repository manager.  
It aims to:
- Track repository state and file contents
- Produce commits signed with Ed25519 keys
- Use strong hashing (blake3) for content and commit identifiers
- Store and reference commits and branches in a compact, verifiable way
- Provide verification of authenticity and integrity for any commit

---

## Architectural Diagram

![Aegis Architecture](aegis_architecture.svg)

The architecture consists of:
1. **User/CLI**: Interface for user commands
2. **Repo Manager**: Core functionality handling operations
3. **Index & Storage**: Manages staged changes and object storage
4. **Commit Creation**: Creates cryptographically signed commits
5. **Verification Path**: Validates signatures and content integrity

---

## High-Level Design

Aegis organizes work around commits and branches using this workflow:
1. **Scan** working directory to create content index (file paths → file hashes)
2. **Create Commit Object**: Contains metadata, snapshot hash, and parent(s)
3. **Sign**: Ed25519 signature over serialized commit data
4. **Store**: Commits and blobs to disk
5. **Reference**: Commits by base58-encoded IDs
6. **Verify**: Re-hash content and verify signature against stored public key

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `anyhow` | Ergonomic error handling |
| `base58` | Human-friendly encoding |
| `blake3` | Cryptographic hashing |
| `chrono` | Timestamps |
| `ed25519_dalek` | Keypair generation/signing |
| `rand` | Randomness for key generation |
| `serde` | Data serialization |
| `walkdir` | Filesystem traversal |
| `whoami` | System user identification |
| `thiserror` | Custom error derivation |

---

## Data Structures

### `Commit`
```rust
struct Commit {
    id: String,                 // Commit ID (blake3 hash)
    parents: Vec<String>,        // Parent commit IDs
    timestamp: DateTime<Utc>,    // Creation time
    author: Author,              // Committer identity
    tree_hash: String,           // Snapshot of all files
    changes: Changes,            // Added/modified/deleted files
    message: String,             // Commit message
    signature: String,           // Ed25519 signature (base58)
    public_key: String,          // Public key (base58)
}


### `Repository`
```rust
struct Repository {
    path: PathBuf,              // Root directory
    aegis_dir: PathBuf,         // .aegis directory
    signing_key: SigningKey,    // Ed25519 signing key
    current_branch: String,     // Active branch
    config: Config,             // Repository configuration
}
```

### `Config`
```rust
struct Config {
    hash_algorithm: String,     // "blake3"
    signature_algorithm: String,// "ed25519"
    uid_length: usize,          // 12
    ignore_patterns: Vec<String>, // [".aegis", "target", ...]
}
```

---

## On-Disk Layout

```
.aegis/
├── branches/       # Branch references
├── commits/        # Commit objects
├── config.yaml     # Repository configuration
├── current_branch  # Active branch name
├── hooks/          # Client-side hooks
├── index           # Staging area
├── keypair.bin     # Ed25519 keypair
├── objects/        # File blobs
├── reflog/         # Reference logs
├── stashes/        # Stashed changes
└── trees/          # Directory structures
```

---

## Command-Line Usage & Internal Workflows

### Core Commands

| Command | Internal Workflow |
|---------|-------------------|
| **`init`**<br>Initialize repository | 1. Create `.aegis` directory structure<br>2. Generate Ed25519 keypair<br>3. Create initial `main` branch<br>4. Set up default ignore patterns |
| **`add <path>`**<br>Stage files | 1. Check pre-add hook<br>2. Hash file contents with blake3<br>3. Update index with file hashes<br>4. Run post-add hook |
| **`commit <message>`**<br>Create commit | 1. Run pre-commit hook<br>2. Compute changes from previous commit<br>3. Create signed commit object<br>4. Store commit and update HEAD<br>5. Print commit summary<br>6. Run post-commit hook |
| **`status`**<br>Show changes | 1. Compare working tree to index<br>2. Compare index to HEAD commit<br>3. Display changes in three categories:<br>   - Changes to be committed<br>   - Changes not staged<br>   - Untracked files |
| **`log`**<br>Show history | 1. Start from HEAD commit<br>2. Traverse parent commits<br>3. Display commit metadata<br>4. Limit to last 50 commits |
| **`verify [commit]`**<br>Verify signatures | 1. Load commit object<br>2. Decode base58 public key<br>3. Verify Ed25519 signature<br>4. Validate content hash |

### Branching & Merging

| Command | Internal Workflow |
|---------|-------------------|
| **`branch [name]`**<br>List/create | 1. List existing branches<br>2. Create new branch at current commit<br>3. Sign branch reference |
| **`checkout <target>`**<br>Switch context | 1. Run pre-checkout hook<br>2. Update HEAD reference<br>3. Reset working tree<br>4. Add reflog entry<br>5. Run post-checkout hook |
| **`merge <branch>`**<br>Merge branches | 1. Find common ancestor<br>2. Detect file conflicts<br>3. Create merge commit with two parents<br>4. Update current branch reference |

### Tagging

| Command | Internal Workflow |
|---------|-------------------|
| **`tag <name> [msg]`**<br>Create tag | 1. Get current commit<br>2. Create signed tag object<br>3. Store in tags directory |
| **`tag -l`**<br>List tags | List all tag files in `.aegis/tags` |

### Stashing

| Command | Internal Workflow |
|---------|-------------------|
| **`stash [msg]`**<br>Save changes | 1. Create tree from current index<br>2. Store stash object<br>3. Reset to HEAD<br>4. Sign stash reference |
| **`stash apply`**<br>Apply stash | 1. Load latest stash<br>2. Detect conflicts<br>3. Apply tree to working directory<br>4. Update index |

### History & Inspection

| Command | Internal Workflow |
|---------|-------------------|
| **`reflog`**<br>Reference log | 1. Parse `HEAD.log` file<br>2. Display last 50 reference changes |
| **`blame <file>`**<br>Line history | 1. Trace file through commit history<br>2. Annotate lines with commit info<br>3. Highlight uncommitted changes |

### Undo Operations

| Command | Internal Workflow |
|---------|-------------------|
| **`revert <commit>`**<br>Undo commit | 1. Compute inverse changes<br>2. Create revert commit<br>3. Update current branch |
| **`reset <commit>`**<br>Reset HEAD | 1. Load target tree<br>2. Remove untracked files<br>3. Restore tracked files<br>4. Update index and HEAD |

### Advanced

| Command | Internal Workflow |
|---------|-------------------|
| **`add -p [path]`**<br>Partial stage | 1. Compute diff hunks<br>2. Prompt user for actions<br>3. Stage selected changes |
| **`ignore <pattern>`**<br>Add ignore | 1. Update config.yaml<br>2. Append to .aegisignore |

---

## Security Considerations

1. **Key Protection**: Private keys stored in `keypair.bin` - set strict file permissions
2. **Signature Verification**: All operations verify signatures before trusting objects
3. **Immutable History**: Signed commits prevent history tampering
4. **Content Addressing**: Blake3 hashes ensure content integrity
5. **UID Generation**: User IDs derived from public keys prevent impersonation

```rust
fn get_public_uid(&self) -> String {
    let hash = blake3::hash(self.signing_key.verifying_key().as_bytes());
    hash.as_bytes()[..8].to_base58()
}
```

---

## Examples

### Initialize Repository
```bash
aegis init
```

### Make First Commit
```bash
aegis add .
aegis commit "Initial commit"
```

### Create Feature Branch
```bash
aegis branch feature-x
aegis checkout feature-x
```

### Verify Commit History
```bash
aegis log
aegis verify HEAD
```

### Merge Changes
```bash
aegis checkout main
aegis merge feature-x
```

### Revert Mistake
```bash
aegis revert abcd1234
```

---

## Developer Notes

1. **Modularization**: Break into modules:
   - `commands/` for CLI operations
   - `storage/` for object handling
   - `crypto/` for signing/verification

2. **Testing Priorities**:
   - Commit serialization/deserialization
   - Signature verification
   - Merge conflict resolution

3. **Enhancements**:
   - Key encryption at rest
   - Compression for object storage
   - Network operations for remote repos
   - Commit graph visualization
```

