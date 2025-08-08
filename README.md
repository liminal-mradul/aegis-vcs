# AegisVCS — Decentralized, Privacy-First Version Control

## 1. Vision & Guiding Principles
**Vision:** Build a developer-first, decentralized version control platform with private, tamper-evident history and optional always-on availability through a federated transistor marketplace.

**Principles**
- **Local-first**: every user has a complete, verifiable history locally.
- **Privacy by default**: private repos stay unreadable to anyone not authorized.
- **Tamper-evident, not tyrannical**: immutable auditability via cryptographic linking and checkpointing; maintainers can still revert with transparent history.
- **Pluggable availability**: peers + transistors provide durability — users choose trade-offs.
- **Interoperable**: easy migration to/from Git to lower friction.

---

## 2. Problem Statement & Value Proposition
### Problems
- Centralized platforms create vendor lock-in, privacy risk, and a single point of failure.
- Offline-first and air-gapped workflows are poorly supported.
- Open-source social credit and contribution graphs are siloed.
- Large repos + binary assets are painful to share in P2P.

### Value
- Decentralized, private collaboration with **no mandatory central server**.
- Optional paid transistors for availability (user-owned, tenant-controlled).
- Reputation/contribution scoring (no money required).
- Snapshot/onboarding to avoid replaying huge histories.

---

## 3. System Overview (Conceptual Components)
### 3.1 Client (CLI & GUI)
- Core commands: init, commit, branch, push, fetch, channel management, score view.
- Local signing, encryption, key management.
- Light client mode: minimal storage, lazy fetch.

### 3.2 Local Daemon (Node)
- Object store, index, local ledger.
- P2P networking (gossip + DHT).
- Snapshot packing/unpacking.

### 3.3 P2P Mesh
- Discovery via DHT.
- Gossip for ledger announcements.
- NAT/relay support.

### 3.4 VCSChain Ledger
- Append-only per-channel ledger.
- Checkpointing with validator signatures.

### 3.5 Active Transistors
- Always-on hosts for availability and snapshots.
- Store encrypted blobs only.

### 3.6 Validator Pool
- Endorses checkpoints.
- Weighted by uptime, service, validation history.

### 3.7 Git Bridge
- Convert Aegis ↔ Git objects.
- Import/export flows.

---

## 4. Core Protocols & Data Model
### 4.1 Objects
- **Blob**: file content chunk.
- **Tree**: directory mapping → blob/tree IDs.
- **Commit**: references tree, parents, metadata, signature.
- **ChannelManifest**: members, policy, encrypted channel keys.
- **LedgerEntry**: `{prevHash, commitHash, signerPubKey, timestamp, meta, signature}`.

### 4.2 Ledger & Checkpoints
- Chained by `prevLedgerHash`.
- Epoch checkpoints: `{epochId, startSeq, endSeq, merkleRoot, validatorSignatures[]}`.

### 4.3 Networking
- **DHT**: maps objectHash → providerNodeIDs.
- **Gossip**: ledger tips/epoch roots.
- **Request/Response**: `GET /objects/{hash}`.

### 4.4 Crypto
- ed25519 for signatures.
- AES-GCM for payload encryption.
- Keys per user & per channel.

---

## 5. Security & Privacy Model
### 5.1 Guarantees
- **Authenticity**: signatures prove origin.
- **Integrity**: hash chains + merkle roots.
- **Confidentiality**: AES-GCM; channel keys encrypted per member.
- **Non-repudiation**: signed ledger & optional anchoring.

### 5.2 Key Management
- Long-term + ephemeral keys.
- Rotation & revocation via ledger.
- Encrypted backups of private keys.

### 5.3 Spam & Abuse
- Rate limits per author/channel.
- Validator endorsement model.
- Reputation affects replication priority.

### 5.4 Threat Mitigation
- Stolen keys → revocation manifests.
- Malicious validators → quorum requirements.
- Sybil → weighted validator admission.

---

## 6. UX & Developer Workflows
### Commit & Push
1. `aegis init` / `aegis clone`
2. `aegis add` → `aegis commit -m "msg"`
3. `aegis push channelX` → ledger entry broadcast + blob upload.

### Offline Work
- Local commits.
- Push queued until online.

### Late Join
- Fetch latest snapshot from transistor.
- Verify signatures.
- Fetch missing blobs.

### Verify Authenticity
- Verify signature → follow `prev` until checkpoint.

---

## 7. MVP Scope & Roadmap
### MVP (
- Local object store + signed commits.
- Simple ledger per channel.
- Direct P2P fetch + basic DHT.
- Minimal transistor: encrypted blob store.
- CLI: init, commit, push, fetch, snapshot.
- Git import/export (basic).

### Phase 2 
- Full DHT provider discovery.
- Epoch checkpointing.
- Snapshots + light clients.
- Transistor marketplace (basic).

### Phase 3 
- Full PoC weighting.
- ZK proof stubs.
- Web UI & Git bridge polish.
- Federation + multi-vendor marketplace.

---

## 8. Tech Strategy
**Hybrid approach**
- **Rust core**: object store, crypto, P2P, ledger verification.
- **TypeScript**: web UI, marketplace services.
- **Python**: tooling, CI helpers.

**Interfacing**
- Local daemon API: HTTP/JSON or gRPC.

---

## 9. Operational Model
### Marketplace
- Vendors publish signed manifest in DHT.
- Client selects vendor, pays, gets token.
- Vendors store ciphertext only.

### Multi-vendor
- Pin to multiple vendors for redundancy.

### Vendor Reputation
- Signed ratings in DHT.
- Aggregated in marketplace UI.

---

## 10. Metrics, Risks, Mitigations
**Metrics**
- Median sync time.
- Onboarding time from snapshot.
- Commit propagation success rate.
- Validator quorum latency.

**Risks**
1. Low adoption → Git interop & outreach.
2. Privacy leak → encryption & multi-vendor.
3. Validator complexity → phased rollout.
4. Storage growth → snapshots & GC.

---

## 11. Governance & Licensing
- **License**: Apache-2.0 (or MIT dual).
- **Code of Conduct** + CLA.
- **Governance**: small core → steering committee.
- **Community**: early adopter program, grants for vendors.

---

## 12. Immediate Next Steps
Pick priority deliverable:
1. MVP dev plan (API + CLI + backlog).
2. Sequence diagrams (commit→push, snapshot restore).
3. Data schema & wire spec.
4. Security spec (keys, revocation, proofs).
5. Pitch + README.

