# Metrice v2.6.0

[English](README.md) | [Türkçe](README.tr.md)

Metrice is a decentralized peer-to-peer (P2P) mesh networking protocol engineered with zero external npm dependencies (Zero-Dependency), running natively on Node.js core libraries (`node:crypto`, `node:net`, `node:dgram`, `node:sqlite`, `node:dns`). It features quantum-resistant cryptography (Post-Quantum Cryptography) and a Tor-like multi-hop onion routing architecture.

The system incorporates NIST FIPS 203 ML-KEM-768 key encapsulation, Ed25519-based RFC 4648 Base32 cryptographic node identities, AutoNAT dialback consensus, Rendezvous persistent reverse tunnels for CGNAT traversal, multi-relay transit bridging (EDGE Transit Routing / `CAP_EDGE_TRANSIT`), Layer 4 HAProxy PROXY Protocol v1 & v2 support, and an embedded in-memory SSH-2 server.

---

## Architecture & Core Components

### 1. Cryptographic Node Identity & Addressing
- **Persistent Key Architecture:** On bootstrap, every node generates an Ed25519 identity key pair (SPKI/PKCS#8 PEM) and a NIST FIPS 203 ML-KEM-768 key pair natively via `node:crypto`. Keys are durably committed to the SQLite `node_identity` table.
- **Deterministic NodeID Derivation:** The raw 32-byte public key extracted from the SPKI DER encoding is hashed with SHA-256. The first 10 bytes (80 bits) of this digest are encoded into an unpadded, lowercase RFC 4648 Base32 string, generating an immutable 16-character global node identifier (`NodeID`) matching `^[a-z2-7]{16}$`.
- **Virtual `.mesh` Domain Namespace:** All network entities are addressed via IP/port-agnostic virtual domain namespaces:
  - User Direct Address: `@user:NodeID.mesh`
  - Federated Channel: `#channel:NodeID.mesh`
  - Global Network Broadcast: `#genel`
  - Local System Console: `SYSTEM_CONSOLE`
- **Signed Frame Integrity:** All routing, tunneling, and presence descriptors dispatched across peers are signed with the source node's Ed25519 private key (`CryptoHelper.sign`) and verified cryptographically by receiving peers (`CryptoHelper.verify`).

### 2. AutoNAT & Reachability Consensus
- **State Machine:** Nodes transition across states: `UNKNOWN` -> `OBSERVING` -> `DIALING` -> `CAP_RELAY` or `CAP_EDGE`.
- **Observed Address Exchange (`observedAddress`):** During P2P cryptographic handshakes, peers report back the observed physical TCP socket address and port of the remote counterpart via `observedAddress`.
- **Reflected Public IP Consensus:** Once at least two independent peers report matching `observedAddress` records, the node establishes consensus regarding its external public IP.
- **Bilateral Dialback Reachability Testing (`DIALBACK_REQUEST` / `DIALBACK_CONFIRM`):**
  - A node initiates verification by issuing a `DIALBACK_REQUEST` containing a 16-byte cryptographic nonce and its listening federation port.
  - The testing peer initiates an outbound TCP dialback to the requesting socket's verified physical address (`socket.realRemoteAddress || socket.remoteAddress`).
  - Upon a successful cryptographic handshake, the peer issues `DIALBACK_CONFIRM`, promoting the node to `CAP_RELAY`. If unreachable (firewalled or CGNAT-bound), the node remains `CAP_EDGE`.
- **SSRF & IP Manipulation Immunity:** Injected `targetIp` fields in dialback requests are discarded; only the verified underlying TCP remote address is targeted. Dialbacks to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback ranges (`127.0.0.0/8`, `::1`) are immediately blocked before socket creation.

### 3. Rendezvous, CGNAT Reverse Tunnels & Transit Routing (CAP_EDGE_TRANSIT)
- **Persistent Reverse TCP Tunnels:** Firewalled `EDGE` nodes establish persistent outbound reverse TCP tunnels to multiple public `RELAY` nodes (`maxEdgeRendezvousRelays`, default: 4).
- **Cryptographic Tunnel Handshake:** Tunnels are authenticated via `RENDEZVOUS_BIND` containing `nodeId`, `identityPublicKey`, `timestamp`, a 16-byte nonce, and an Ed25519 signature; relays acknowledge via `RENDEZVOUS_ACK`.
- **Single-Byte Keepalive Heartbeat:** To keep stateful NAT and firewall tables open without JSON overhead, nodes exchange 1-byte control frames: `0x09` (PING) and `0x0A` (PONG) every 30 seconds.
- **Dynamic Role Escalation (`CAP_EDGE_TRANSIT`):** An `EDGE` node maintaining active reverse tunnels to at least 2 independent relays with `ALLOW_EDGE_ROUTING=true` dynamically ascends to `CAP_EDGE_TRANSIT`.
- **Bidirectional In-and-Out Tunnel Bridging:** Transit nodes route traffic across distinct reverse tunnels, allowing segmented relays and firewalled edges to exchange packets without direct IP connectivity.
- **Homogeneous, Loop-Free Gossip Bridging:** Transit nodes cross-bridge presence announcements (`PRESENCE_ANNOUNCE`) and global `#genel` channel traffic across connected relays with packet deduplication filters (`ALLOW_EDGE_GOSSIP=true`).
- **Resource Hardening:** Relays limit concurrent reverse tunnels to 64 (`maxRendezvousTunnels`) to prevent memory and file descriptor exhaustion.

### 4. 3-Hop Telescopic Post-Quantum Onion Routing
- **Anonymous 3-Hop Circuits:** Packets traverse telescopic 3-hop circuits to conceal network topology and packet provenance:
  1. Inbound Guard Node
  2. Intermediate Relay or `CAP_EDGE_TRANSIT` Node
  3. Outbound Exit Node
- **Hybrid Relay Selection Pool:** Circuit construction (`relayPool`) blends backbone `RELAY` nodes with `CAP_EDGE_TRANSIT` edge nodes to maximize path entropy and resist traffic analysis.
- **NIST FIPS 203 ML-KEM-768 Key Encapsulation:** Each hop negotiates ephemeral symmetric keys via post-quantum Kyber-768 (`crypto.encapsulate` / `crypto.decapsulate`), deriving fresh 32-byte symmetric session keys.
- **Layered Onion Peeling:** The initiator wraps user payloads in reverse order using AES-256-GCM authenticated encryption. Each intermediary decrypts its own single layer, exposing only the next circuit hop (`circuitId`) without knowing the origin or destination.
- **Uniform 2048-Byte Cell Padding:** To eliminate side-channel packet size fingerprinting, all onion frames (`ONION_CELL`) are strictly padded to 2048 bytes. User payloads are capped at 768 bytes (`MAX_ONION_PAYLOAD`), with the remainder filled with cryptographically pseudorandom bytes.
- **Circuit Lifecycle & Teardown:** Circuits are retired and purged from memory and SQLite `active_circuits` after 10 minutes (`CIRCUIT_TTL_MS = 600000`) to mitigate long-term traffic correlation.

### 5. Distributed Presence & SQLite Routing
- **Signed Presence Descriptors:** Nodes advertise active users and channel subscriptions via Ed25519-signed `PRESENCE_ANNOUNCE` gossip packets.
- **IP Address Scrubbing:** Physical IP addresses are scrubbed from presence frames; peer reachability is resolved exclusively through virtual domain identities (`.mesh`).
- **Gossip Fanout with Deduplication:** Received presence updates are propagated to peers with broadcast storm suppression through in-memory message ID cache tracking.
- **Bilateral Synchronization:** When two nodes connect, they perform a bilateral exchange of known presence tables; reverse-tunneled edge clients are seamlessly propagated.
- **SQLite Routing Persistence & TTL:** Ephemeral routes are recorded in the SQLite `routing_table` with a `last_seen` timestamp. Inactive entries expire and are pruned automatically after 60 seconds (`PRESENCE_TTL_MS`).

### 6. In-Memory SSH-2 Server & Two-Factor Vault Authentication
- **Zero-Dependency Native SSH-2:** Built on pure JavaScript without relying on OpenSSH system daemons (`sshd`) or C/C++ native addons (RFC 4253, RFC 4252, RFC 4254).
- **Cryptographic Protocol Stack:**
  - Key Exchange: `curve25519-sha256`
  - Server Host Key: `ssh-ed25519`
  - Symmetric Cipher: `aes128-ctr` or `aes256-gcm`
- **Dynamic Version Synchronisation:** Server identification string (`sshServerVersion`) synchronizes dynamically with `package.json` (`SSH-2.0-Metrice_2.6.0`) and is configurable via `SSH_SERVER_VERSION`.
- **Two-Factor Hardware Key Binding (2FA Vault):**
  - Passwords are never verified directly. The password is salted with the client's physical Ed25519 public key (32 bytes).
  - Stretched via Scrypt (N=16384, r=8, p=1, maxmem 64 MB).
  - Derived through HKDF-SHA256 with info `metrice-vault-seed-v2` and salt `metrice-vault-salt:${nodeAddress}` to generate a 32-byte vault seed.
  - The node validates the sentinel token `METRICE_VAULT_SENTINEL_V1`. Even with a valid password, authentication is rejected if the connecting client's Ed25519 key does not match the user's registered public keys (`public_keys`).

### 7. Layer 4 HAProxy PROXY Protocol v1 & v2 Support
- **Transparent Source Resolution:** Resolves physical client IPs and ports (`realRemoteAddress`, `realRemotePort`) when deployed behind Layer 4 proxies (HAProxy, Nginx Stream, AWS NLB, Traefik) via `USE_PROXY_PROTOCOL=true`.
- **Dual Format Parsing:**
  - PROXY v1: US-ASCII text lines (`PROXY TCP4/TCP6/UNKNOWN ...\r\n`).
  - PROXY v2: 12-byte binary magic header (`\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`), command bytes, family, and binary IPv4/IPv6 addresses.
- **IP Spoofing Immunity:** Only proxies listed in `PROXY_TRUSTED_IPS` (default: `127.0.0.1,::1`) are authorized. Spoofing attempts from unauthorized IPs are rejected with immediate socket termination (`status: REJECT`).
- **Transparent Passthrough (Unshift):** Non-PROXY traffic has read buffer bytes restored (`socket.unshift(remainder)`), routing seamlessly to federation, SSH, or Telnet handlers with zero data loss.

### 8. Dedicated TCP Health & Heartbeat Server (Port 8050)
- **Dedicated Health Port (`HEALTH_PORT`):** Operates an isolated, lightweight TCP service on port 8050 (`src/core/healthServer.js`) dedicated to Docker `HEALTHCHECK`, Kubernetes liveness/readiness probes, and orchestrators.
- **Federation Traffic Isolation:** Health probes no longer connect to federation port 8001, eliminating loopback log pollution and tunnel handshake overhead every 30 seconds.
- **Security & Network Isolation:** Binds strictly to `127.0.0.1` by default; can be exposed to external monitors via `ALLOW_OUTER_HEARTBEAT=true` on `0.0.0.0`.
- **Streaming Command Protocol:**
  - `PING`: Liveness probe; returns `PONG\n`.
  - `HEALTH`: Quick database integrity and uptime check; returns `OK {"status":"healthy",...}\n`.
  - `STATUS` / `INFO`: Full telemetry dump (Uptime, RSS/Heap memory metrics, SQLite WAL status, active Rendezvous tunnels, active circuits, known/verified peer counts, ML-KEM status).
  - `QUIT`: Gracefully closes the connection.

### 9. Wire Framing, Buffer Limiting & Anti-Replay Defense
- **Security Buffer Threshold (`SECURE_BUFFER_LIMIT`):** Sockets accumulating over 64 KB (`SECURE_BUFFER_LIMIT = 65536` bytes) without a newline delimiter or sending non-JSON (`{`) payloads are destroyed immediately to mitigate buffer overflow, Slowloris, and OOM attacks.
- **Cryptographic Nonce Pool (Anti-Replay):** Every handshake and tunnel bind frame carries a 16-byte cryptographically random `nonce`. Observed nonces are retained in an in-memory TTL pool; duplicate nonces are rejected.
- **Timestamp Skew Validation:** Packet timestamps are checked against system clocks with tight drift tolerances to prevent delayed replay injections.
- **`ENCRYPTED_FRAME` Envelope:** Sensitive P2P payloads are encapsulated in authenticated AES-256-GCM envelopes containing a 12-byte IV, 16-byte Auth Tag, and ciphertext.

### 10. Zero-Dependency SQLite Storage Engine & Outbox Queue
- **Built-in `node:sqlite` (`DatabaseSync`):** Direct integration with Node.js built-in SQLite engine without external npm packages (`sqlite3`, `better-sqlite3`) or C++ compiler toolchains (`node-gyp`).
- **WAL Mode & Concurrent Throughput:** Configured with `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = NORMAL;` to eliminate read/write lock contention.
- **Comprehensive Schema:**
  - `node_identity`: Persistent Ed25519 and ML-KEM-768 key pairs.
  - `profiles`: User contacts, password hashes, registered public keys (`public_keys`), KEM public keys, and Telnet authorization flags.
  - `messages`: Private and channel chat history, E2EE flags, and user deletion markers.
  - `trusted_keys`: Verified peer cryptographic keys.
  - `routing_table`: Ephemeral peer routing entries with TTL tracking.
  - `active_circuits`: 3-hop circuit symmetric keys and hop mappings.
  - `outbox`: Pending messages destined for offline peers.
- **Outbox Retry Engine:** When sending messages to an offline recipient, messages are spooled in `outbox`. Messages are retried using exponential backoff or immediately flushed when a `PRESENCE_ANNOUNCE` reveals the recipient is back online.

### 11. Multi-Language Interactive TUI & ANSI Session Engine
- **Pure JavaScript ANSI/VT100 Engine:** Built without external terminal UI frameworks (blessed, ink); manages cursor positioning, colors, and screen buffers via standard escape sequences (`src/utils/ansi.js`).
- **Unified Terminal Session (`TerminalSession`):** Dual-mode terminal engine abstracting both Telnet NVT (RFC 854) and SSH-2 PTY channels (`src/core/terminalSession.js`).
- **Modular Command Registry (`CommandRegistry`):** Interactive commands (`/join`, `/msg`, `/keys`, `/status`, `/who`, `/peers`, `/help`, etc.) are decoupled under `src/commands/modules/` with permission checks (`requireAuth`) and argument parsing.
- **Full Bilingual Localization (`I18n`):** System logs, terminal banners, command outputs, and error messages support real-time localization in Turkish (`src/locales/tr.js`) and English (`src/locales/en.js`).

### 12. Telnet Access Barrier & Plaintext Protection
- **Plaintext Password Protection:** To prevent password sniffing over untrusted local networks or the internet, user profiles include an `allow_telnet` security flag.
- **Default Restriction with SSH Authorization:** Password authentication over Telnet is restricted by default; users can enable Telnet access only from within an authenticated, encrypted SSH-2FA session via `/allowtelnet`.

---

## Installation & Quick Start

### Prerequisites
- Node.js v22.0.0 or higher (Node.js v24+ recommended for native hardware-accelerated ML-KEM-768).
- Operating System: Linux, macOS, BSD, Windows.
- Zero external package dependencies (`npm install` is not required).

```bash
git clone git@github.com:GokturkA1/metrice.git
cd metrice
node src/index.js
```

---

## Deployment Models

Metrice is designed for production deployment across VDS/VPS instances, Docker/Podman containers, reverse proxies (Nginx, Traefik, HAProxy), and tunneling services (Cloudflared, Ngrok).

### 1. Public IP RELAY Node (VDS)
```bash
SERVER_NAME="relay1.metrice.network" \
FED_PORT=8001 \
SSH_PORT=2224 \
CLIENT_PORT=2222 \
MESH_ROLE=RELAY \
node src/index.js
```

### 2. Docker & Docker Compose Deployment (Guaranteed Data Persistence)

Metrice provides a security-hardened [Dockerfile](Dockerfile) and [docker-compose.yml](docker-compose.yml) adhering to container best practices (Rootless `node` user, TCP health checks, automatic `VOLUME ["/app/data"]` persistence).

> **Important (Data Persistence):** SQLite database files (`data_8001.db`) and peer caches (`peers_8001.json`) are stored in `/app/data/`. Because the host `./data` directory is mapped to this path, user profiles, public keys, and message history remain fully preserved across container rebuilds (`docker build`) or upgrades.

#### Method A: Launch with Docker Compose (Recommended)
```bash
# 1. Build and start the container in detached mode:
docker compose up -d --build

# 2. Monitor real-time logs:
docker compose logs -f

# 3. Stop the node:
docker compose down
```

#### Method B: Launch with Standalone Docker CLI
```bash
# 1. Build the hardened container image:
docker build -t metrice .

# 2. Create the host data directory and set permissions (UID 1000 node user):
mkdir -p data
chown -R 1000:1000 data 2>/dev/null || true

# 3. Run with persistent volume and environment variables:
# (Note: SERVER_NAME is optional; AutoNAT resolves public IP dynamically)
docker run -d \
  --name metrice-node \
  --restart always \
  -e TRUST_PROXY=true \
  -e MESH_ROLE=RELAY \
  -e FED_PORT=8001 \
  -e SSH_PORT=2224 \
  -e CLIENT_PORT=2222 \
  -e DB_FILE=/app/data/data_8001.db \
  -e PEER_FILE=/app/data/peers_8001.json \
  -p 8001:8001 \
  -p 2224:2224 \
  -p 2222:2222 \
  -v $(pwd)/data:/app/data \
  metrice
```

#### Method C: Pull Prebuilt Official Image (GitHub Container Registry)
Deploy instantly without compiling from source using multi-arch (`linux/amd64` and `linux/arm64`) official images:
```bash
# Pull the prebuilt image:
docker pull ghcr.io/gokturka1/metrice:latest

# Run using the prebuilt GHCR image:
docker run -d \
  --name metrice-node \
  --restart always \
  -e TRUST_PROXY=true \
  -e MESH_ROLE=RELAY \
  -e FED_PORT=8001 \
  -e SSH_PORT=2224 \
  -e CLIENT_PORT=2222 \
  -e DB_FILE=/app/data/data_8001.db \
  -e PEER_FILE=/app/data/peers_8001.json \
  -p 8001:8001 \
  -p 2224:2224 \
  -p 2222:2222 \
  -v $(pwd)/data:/app/data \
  ghcr.io/gokturka1/metrice:latest
```

### 3. Behind Tunneling Proxies (Cloudflared / Ngrok)
```bash
TRUST_PROXY=true \
SERVER_NAME="mesh.domain.com" \
SSH_SERVER_VERSION="SSH-2.0-SecureMesh_2.0" \
node src/index.js
```

### 4. Behind HAProxy / L4 Reverse Proxy with PROXY Protocol
Sample HAProxy configuration snippet:

```haproxy
frontend metrice_ssh_in
    bind *:2224
    mode tcp
    default_backend metrice_ssh_nodes

backend metrice_ssh_nodes
    mode tcp
    server srv1 127.0.0.1:2224 send-proxy-v2
```

Launch node with PROXY protocol enabled:
```bash
USE_PROXY_PROTOCOL=true \
PROXY_TRUSTED_IPS="127.0.0.1,::1" \
SSH_PORT=2224 \
FED_PORT=8001 \
node src/index.js
```

---

## Configuration Reference

All settings can be configured via environment variables (`process.env`) or `src/config/index.js`:

| Parameter | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `serverName` | `SERVER_NAME` | `'localhost'` | Node public domain or hostname |
| `clientPort` | `CLIENT_PORT` | `2222` | Telnet TUI listening TCP port |
| `sshPort` | `SSH_PORT` | `2224` | Post-Quantum SSH-2 listening TCP port |
| `federationPort` | `FED_PORT` | `8001` | P2P Federation and Onion listening TCP port |
| `publicFederationPort` | `PUBLIC_FED_PORT` / `FED_PUBLIC_PORT` | `FED_PORT` (8001) | Public federation port announced to peers and dialback target |
| `publicSshPort` | `PUBLIC_SSH_PORT` / `SSH_PUBLIC_PORT` | `SSH_PORT` (2224) | Public SSH port announced to peers |
| `publicClientPort` | `PUBLIC_CLIENT_PORT` / `CLIENT_PUBLIC_PORT` | `CLIENT_PORT` (2222) | Public Telnet TUI port announced to peers |
| `healthPort` | `HEALTH_PORT` | `8050` | TCP Health and Heartbeat listening port |
| `allowOuterHeartbeat` | `ALLOW_OUTER_HEARTBEAT` | `false` | Allow outer network access to TCP Health port on `0.0.0.0` (Default: `127.0.0.1` only) |
| `sshServerVersion` | `SSH_SERVER_VERSION` | `'SSH-2.0-Metrice_2.6.0'` | SSH server identification banner |
| `meshRole` | `MESH_ROLE` | `'EDGE'` | Node routing role (`'RELAY'` or `'EDGE'`) |
| `bootstrapPeers` | `BOOTSTRAP_PEERS` | `''` | Comma-separated list of static bootstrap relay peers |
| `maxRendezvousTunnels`| `MAX_RENDEZVOUS_TUNNELS` | `64` | Maximum incoming reverse tunnels a RELAY accepts |
| `rendezvousKeepaliveInterval` | `RENDEZVOUS_KEEPALIVE_MS` | `30000` | Reverse tunnel keepalive interval (PING/PONG ms) |
| `presenceTtl` | `PRESENCE_TTL_MS` | `60000` | Routing table presence expiration TTL (ms) |
| `circuitTtl` | `CIRCUIT_TTL_MS` | `600000` | Onion circuit lifespan (ms) |
| `uniformCellSize` | `UNIFORM_CELL_SIZE` | `2048` | Constant onion cell size in bytes |
| `secureBufferLimit` | `SECURE_BUFFER_LIMIT` | `65536` | Framing buffer security threshold (64 KB) |
| `trustProxy` | `TRUST_PROXY` | `false` | Header resolution tolerance behind reverse proxies |
| `useProxyProtocol` | `USE_PROXY_PROTOCOL` | `false` | Enable HAProxy PROXY Protocol v1 & v2 parsing |
| `proxyProtocolTrustedIps` | `PROXY_TRUSTED_IPS` | `'127.0.0.1,::1'` | Comma-separated trusted proxy IPs |
| `allowEdgeRouting` | `ALLOW_EDGE_ROUTING` | `true` | Enable dynamic CAP_EDGE_TRANSIT promotion on multi-homed EDGE |
| `allowEdgeGossip` | `ALLOW_EDGE_GOSSIP` | `true` | Enable cross-relay presence gossip bridging on transit nodes |
| `maxEdgeRendezvousRelays` | `MAX_EDGE_RENDEZVOUS_RELAYS` | `4` | Maximum relays an EDGE node binds to |
| `strictPq` | `STRICT_PQ` | `false` | Enforce pure Post-Quantum ML-KEM mode (disable classic fallbacks) |
| `dbFile` | `DB_FILE` | `./data_<PORT>.db` | SQLite database file path |
| `peerCacheFile` | `PEER_FILE` | `./peers_<PORT>.json` | Known peer cache file path |
| `logLevel` | `LOG_LEVEL` | `'DEBUG'` | Log verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`) |

---

## Interactive Client Interface

### 1. SSH Connection (Recommended)
```bash
ssh -p 2224 username@server_address
```
On initial login, your local Ed25519 public key is securely bound to your account.

### 2. Telnet Connection (Local Testing)
```bash
telnet server_address 2222
```

### 3. TUI Terminal Commands
Available commands in the interactive terminal:

- `/join #channel:NodeID.mesh`: Subscribe to a remote federated channel.
- `/leave #channel`: Unsubscribe from a channel.
- `/remove @user`: Purge chat history with a specific peer.
- `/msg @target <message>`: Dispatch end-to-end encrypted direct message.
- `/keys add <ssh-ed25519 ...>`: Register an additional Ed25519 public key.
- `/keys list`: Display all registered authorized keys.
- `/status`: Display node role, identity, and active rendezvous tunnels.
- `/help`: Print command reference.
- `/quit`: Terminate the interactive session.

---

## Wire Protocol Formats

### Handshake (`HANDSHAKE_INIT` / `HANDSHAKE_REPLY`)
```json
{
  "type": "HANDSHAKE_INIT",
  "nodeAddress": "host:port",
  "identityPublicKey": "base64_ed25519_pubkey",
  "kemPublicKey": "base64_kyber768_pubkey",
  "nonce": "16_byte_hex",
  "sig": "ed25519_signature"
}
```

### AutoNAT Dialback (`DIALBACK_REQUEST` / `DIALBACK_CONFIRM`)
```json
{
  "type": "DIALBACK_REQUEST",
  "targetPort": 8001,
  "nonce": "16_byte_hex"
}
```

### Rendezvous Reverse Tunnel (`RENDEZVOUS_BIND` / `RENDEZVOUS_ACK`)
```json
{
  "type": "RENDEZVOUS_BIND",
  "nodeId": "16_char_base32",
  "identityPublicKey": "base64_ed25519_pubkey",
  "timestamp": 1788732000,
  "nonce": "16_byte_hex",
  "sig": "ed25519_signature"
}
```

### Onion Routing (`CIRCUIT_CREATE`, `CIRCUIT_EXTEND`, `ONION_CELL`)
```json
{
  "type": "ONION_CELL",
  "circuitId": "16_byte_hex",
  "iv": "base64_aes_gcm_iv",
  "authTag": "base64_tag",
  "ciphertext": "base64_encrypted_payload",
  "pad": "000... (Strict 2048-byte uniform size)"
}
```

### HAProxy PROXY Protocol v1 & v2 (L4 Header Format)
```text
# PROXY v1 (US-ASCII Text)
PROXY TCP4 203.0.113.195 198.51.100.1 56324 8001\r\n<payload>

# PROXY v2 (12-Byte Binary Magic + IPv4/IPv6 Address Block)
\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C...<payload>
```

### TCP Health & Heartbeat Protocol (Port 8050)
```text
# Liveness Probe:
Client: PING\n
Server: PONG\n

# Quick Health Check Probe:
Client: HEALTH\n
Server: OK {"status":"healthy","uptime":3600,"database":"healthy","timestamp":1789139924935}\n

# Full Telemetry Status Dump:
Client: STATUS\n
Server: {"status":"healthy","version":"2.6.0","serverName":"relay1.metrice.network","nodeAddress":"...","meshRole":"RELAY","uptimeSeconds":3600,"timestamp":1789139924935,"database":{"status":"healthy","walMode":true},"federation":{"port":8001,"activeRendezvousTunnels":4,"maxRendezvousTunnels":64,"activeCircuits":2},"peers":{"totalKnown":12,"verified":8},"quantumSecurity":{"mlkem768":true,"strictPq":false},"memory":{"rssMb":42.5,"heapUsedMb":18.2}}\n

# Graceful Termination:
Client: QUIT\n
```

---

## Verification & Test Suites

System correctness and protocol resilience are enforced across six comprehensive test suites (154 tests total) and automated GitHub Actions CI/CD workflows:

```bash
# Execute the entire test suite:
npm test

# Run individual test suites:
node tests/mesh.test.js       # 1. P2P-Mesh, AutoNAT, Rendezvous, PROXY & Transit Routing Suite (83 Tests)
node tests/protocol.test.js   # 2. Wire Protocol, Discovery, Post-Quantum SSH-2 & DB Suite (24 Tests)
node tests/security.test.js   # 3. Security Audit, Nonce Replay, DoS, SSRF & PROXY Spoofing Suite (10 Tests)
node tests/presence.test.js   # 4. Presence Sync, Gossip Flooding, Stale Drop & Keepalive Suite (8 Tests)
node tests/crypto-kat.test.js # 5. Cryptographic Known Answer Tests (RFC 8032, NIST FIPS 203, KDF) (10 Tests)
node tests/health.test.js     # 6. TCP Health & Heartbeat Protocol Test Suite (19 Tests)
```

Test coverage encompasses Base32 node ID derivation, AutoNAT dialback consensus, PROXY Protocol parsing and spoofing protection, `CAP_EDGE_TRANSIT` dynamic promotion and cross-bridging, buffer overflow thresholds, ML-KEM-768 onion routing, SSRF safeguards, two-factor SSH vault authentication, and real-time mesh presence synchronization.

Additionally, GitHub Actions runs on every push and pull request:
- Multi-version matrix on `Node.js 24.x` and `Node.js 26.x`,
- `Oxlint` standalone static analysis (`--deny-warnings`),
- Zero external dependencies verification audit,
- `Docker` image build & container startup sanity check,
- `CodeQL` Static Application Security Testing (SAST).

---

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See [LICENSE](LICENSE) for details.
