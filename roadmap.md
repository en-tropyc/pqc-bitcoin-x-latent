# Falcon Signature Aggregation & Quantum Proof-of-Work Integration

Development plan for integrating Falcon signature aggregation and Quantum Proof-of-Work (Q-PoW).

---

### 1. Current status of `pqc-bitcoin`

| Area                   | What is already there                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------------------- |
| PQC primitives         | Kyber, FrodoKEM and NTRU added next to ECDSA; hybrid (classical + PQC) key handling; new P2QRH\* address type |
| Signing / verification | Additional `OP_CHECKPQCVERIFY` opcode; wallet RPC can create PQC‐only or hybrid transactions                  |
| Build & config         | Autotools flag `--with-pqc=kyber,…` and per-node service-bit advertisement                                    |

\*Pay-to-Quantum-Resistant-Hash; analogous to P2WPKH.

---

### 2. Architecture alignment

| Layer              | pqc-bitcoin baseline                    |
| ------------------ | --------------------------------------- |
| **Consensus**      | Classic SHA-256 PoW                     |
| **Crypto library** | Liboqs-backed KEM/SIG modules           |
| **Script VM**      | `OP_CHECKPQCVERIFY`                     |
| **P2P features**   | `NODE_PQC` service bit                  |
| **Wallet / RPC**   | PQC key generation, single-sig spending |

---

### 3. Integration scope (three incremental work-packages)

| WP                                             | Objective                                         | Key tasks                                                                                                                              |
| ---------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **WP-A — Falcon aggregation**                  | Block-level support for your BLS-style aggregator | 1. Embed `libfalcon_agg` under `src/crypto/falconagg/`<br>2. New script opcode & interpreter path<br>3. Wallet RPC + GUI toggle        |
| **WP-B — Quantum PoW**                         | Swap SHA-256 double-hash with Q-PoW function      | 1. Add `qpow_hash()` in `src/pow_q.cpp`<br>2. Difficulty-adjust & header version bump<br>3. Miner reference implementation (CPU)       |
| **WP-C — Network handshake & rolling upgrade** | Ensure mixed nodes don't stall                    | 1. Advertise new service bits<br>2. "segwit-style" feature-bits in block version<br>3. Soft-fork activation via BIP-9 style signalling |

---

### 4. Initial testnet setup

| Parameter        | Value                                                                       |
| ---------------- | --------------------------------------------------------------------------- |
| Chain ID         | **pqt-test**                                                                |
| Genesis          | Falcon dev-key multisig, Q-PoW target = 2²⁵⁵                                |
| Ports            | p2p = 19444, rpc = 19443                                                    |
| Address prefixes | P2QRH `q`, Falcon-agg `qA`                                                  |
| Docker bundle    | `bitcoind-pqc`, `falcon-aggregatord`, `qpw-minerd`                          |
| CI               | GitHub Actions: build, regtest (100 blocks), Falcon-agg spend, Q-PoW verify |

Deployment steps:

1. **Fork & branch**
   `qpo​​w-falcon-dev` off latest `pqc-bitcoin` `main`.
2. **Automated build**
   `./configure --with-pqc=kyber,falcon --enable-qpow`.
3. **Spin testnet**
   `docker-compose up` – nodes sync; aggregator signs ≥ 20-input tx; miner solves Q-PoW.
4. **Metrics & dashboards**
   Prometheus exporter + Grafana: aggregate-size, sig-compression ratio, average Q-PoW solve time.

---

### 5. Next steps
- [ ] Clone repo, run unit tests
- [ ] Implement `libfalcon_agg` wrapper + tests                    
- [ ] Draft `OP_FALCONAGGVERIFY` opcode spec                       
- [ ] Integrate Q-PoW hash, regenerate genesis                     
- [ ] Docker testnet, publish connect instructions                 
- [ ] Internal security review; open collaboration PRs to QBlockQ  

---

