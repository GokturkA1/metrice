# Metrice v2.5.10

[English](README.md) | [Türkçe](README.tr.md)

Metrice is a decentralized peer-to-peer (P2P) mesh networking protocol engineered with zero external npm dependencies (Zero-Dependency), running natively on Node.js core libraries (`node:crypto`, `node:net`, `node:dgram`, `node:sqlite`, `node:dns`). It features quantum-resistant cryptography (Post-Quantum Cryptography) and a Tor-like multi-hop onion routing architecture.

The system incorporates NIST FIPS 203 ML-KEM-768 key encapsulation, Ed25519-based RFC 4648 Base32 cryptographic node identities, AutoNAT dialback consensus, Rendezvous persistent reverse tunnels for CGNAT traversal, multi-relay transit bridging (EDGE Transit Routing / `CAP_EDGE_TRANSIT`), Layer 4 HAProxy PROXY Protocol v1 & v2 support, and an embedded in-memory SSH-2 server.

---

## Architecture & Core Components

### 1. Cryptographic Node Identity & Addressing
- Every node maintains a persistent Ed25519 identity key pair.
- The 16-character Node ID (`NodeID`) is derived from the first 10 bytes (80 bits) of the SHA-256 digest of the raw Ed25519 public key encoded in RFC 4648 Base32 (`^[a-z2-7]{16}$`).
- Network addressing is completely IP/Port agnostic using virtual `.mesh` domain namespaces:
  - User Address: `@user:NodeID.mesh`
  - Federated Channel: `#channel:NodeID.mesh`
  - Global Mesh Channel: `#genel`

### 2. AutoNAT & Reachability Consensus
- Nodes exchange their observed peer addresses (`observedAddress`) during the cryptographic handshake.
- A Reflected Public IP consensus is established once at least two independent peers report consistent observations.
- Nodes initiate reachability testing by transmitting a `DIALBACK_REQUEST` containing a cryptographic nonce.
- The target peer attempts a TCP dialback connection to the requesting node's physical remote address (`socket.realRemoteAddress || socket.remoteAddress`). If verified, the node attains the `CAP_RELAY` role; otherwise, it remains in `CAP_EDGE`.
- **SSRF Defense:** Injected `targetIp` values inside `DIALBACK_REQUEST` are strictly discarded; only the verified physical TCP socket remote address is used. Dialbacks targeting RFC 1918 private networks or loopback addresses are blocked.

### 3. Rendezvous, CGNAT Reverse Tunnels & Transit Routing (CAP_EDGE_TRANSIT)
- Firewalled or CGNAT-bound `EDGE` nodes establish persistent reverse TCP tunnels to multiple publicly reachable `RELAY` nodes (`maxEdgeRendezvousRelays`, default: 4).
- Tunnel sessions are authenticated via Ed25519 cryptographic signatures in `RENDEZVOUS_BIND` packets.
- Firewall session state is preserved through 30-second single-byte keepalives: `0x09` (PING) and `0x0A` (PONG).
- Active tunnel capacity per relay is bounded to 64 to prevent resource exhaustion (`maxRendezvousTunnels`).
- **Dynamic Role Escalation (`CAP_EDGE_TRANSIT`):** An EDGE node connected to at least two independent relays with `ALLOW_EDGE_ROUTING=true` dynamically ascends to `CAP_EDGE_TRANSIT`, enabling bidirectional in-and-out reverse tunnel bridging between segmented relays.
- **Loop-Free Gossip Bridging:** Transit edge nodes cross-bridge presence announcements (`PRESENCE_ANNOUNCE`) and global `#genel` messages between relays without broadcast loops (`ALLOW_EDGE_GOSSIP=true`).

### 4. 3-Hop Telescopic Post-Quantum Onion Routing
- Anonymous 3-hop circuits (Inbound Guard, Relay/Transit, Outbound Exit) conceal network topology and packet trajectories.
- The circuit selection pool (`relayPool`) integrates both backbone `RELAY` nodes and `CAP_EDGE_TRANSIT` nodes to enhance routing diversity.
- Each hop negotiates ephemeral symmetric keys via NIST FIPS 203 ML-KEM-768 (Kyber-768) key encapsulation.
- **Traffic Analysis & DPI Resistance:** All onion cells (`ONION_CELL`) are padded to a strict uniform length of 2048 bytes (Uniform Cell Padding). Raw payloads are capped at 768 bytes (`MAX_ONION_PAYLOAD`).
- Cells are never exposed in plaintext; transport is secured inside AES-256-GCM `ENCRYPTED_FRAME` blocks.

### 5. Distributed Presence & SQLite Routing
- Presence and channel subscriptions are propagated across the mesh using Ed25519-signed `PRESENCE_ANNOUNCE` gossip packets.
- Raw IP addresses are scrubbed from gossip frames; announcements reference only virtual domain names or `.mesh` identifiers.
- Ephemeral routing entries are cached in memory and committed to the SQLite `routing_table`. Inactive records expire automatically after 60 seconds (TTL).

### 6. In-Memory SSH-2 Server & Two-Factor Vault Authentication
- Pure JavaScript SSH-2 server operates natively without requiring external system daemons (`sshd`).
- **Dynamic Version Synchronisation:** Server identification string (`sshServerVersion`) dynamically aligns with `package.json` through `src/version.js` (default: `SSH-2.0-Metrice_2.5.10`) and remains configurable via environment variables.
- **Two-Factor Ephemeral Vault Derivation:** User passwords are salted with the client's Ed25519 public key and derived via Scrypt (N=16384, r=8, p=1) and HKDF-SHA256. Authentication fails without the registered physical Ed25519 key, even if the password is correct.

### 7. Layer 4 HAProxy PROXY Protocol v1 & v2 Support
- Nodes operating behind Layer 4 reverse proxies (HAProxy, Nginx Stream, AWS NLB) transparently resolve real client IP addresses and ports (`realRemoteAddress`, `realRemotePort`) with `USE_PROXY_PROTOCOL=true`.
- Supports both US-ASCII text PROXY v1 (`PROXY TCP4/TCP6/UNKNOWN`) and 12-byte binary magic PROXY v2 with zero external libraries.
- **IP Spoofing Immunity:** Only proxies specified in `PROXY_TRUSTED_IPS` (default: `127.0.0.1,::1`) are authorized. Unauthorized spoofing attempts are instantly rejected with immediate socket termination (`status: REJECT`).
- **Transparent Passthrough:** Direct connections without PROXY headers have unparsed bytes restored (`socket.unshift(remainder)`) and route seamlessly to federation, SSH, or Telnet handlers with zero data loss.

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
| `sshServerVersion` | `SSH_SERVER_VERSION` | `'SSH-2.0-Metrice_2.5.10'` | SSH server identification banner |
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

---

## Verification & Test Suites

System correctness and protocol resilience are enforced across five comprehensive test suites (135 tests total) and automated GitHub Actions CI/CD workflows:

```bash
# Execute the entire test suite:
npm test

# Run individual test suites:
node tests/mesh.test.js       # 1. P2P-Mesh, AutoNAT, Rendezvous, PROXY & Transit Routing Suite (83 Tests)
node tests/protocol.test.js   # 2. Wire Protocol, Discovery, Post-Quantum SSH-2 & DB Suite (24 Tests)
node tests/security.test.js   # 3. Security Audit, Nonce Replay, DoS, SSRF & PROXY Spoofing Suite (10 Tests)
node tests/presence.test.js   # 4. Presence Sync, Gossip Flooding, Stale Drop & Keepalive Suite (8 Tests)
node tests/crypto-kat.test.js # 5. Cryptographic Known Answer Tests (RFC 8032, NIST FIPS 203, KDF) (10 Tests)
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
