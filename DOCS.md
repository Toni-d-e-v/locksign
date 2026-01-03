# 🔐 locksign - Technical Documentation

**Secure, In-Memory Blockchain Signing Service for Ethereum & Solana**

Version 0.1.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Installation & Setup](#3-installation--setup)
4. [Configuration](#4-configuration)
5. [Key Management](#5-key-management)
6. [Policy Engine](#6-policy-engine)
7. [gRPC API Reference](#7-grpc-api-reference)
8. [Security Considerations](#8-security-considerations)
9. [Docker Deployment](#9-docker-deployment)
10. [Troubleshooting](#10-troubleshooting)
11. [Project Structure](#11-project-structure)
12. [Roadmap](#12-roadmap)

---

## 1. Overview

### 1.1 What is locksign?

locksign is an open-source, self-hosted signing service designed for security-first blockchain operations. It provides a secure way to manage and use private keys for Ethereum and Solana blockchains without ever exposing the raw keys to connected applications.

### 1.2 Key Features

- **Encrypted at Rest** - Private keys are AES-256-GCM encrypted on disk using Argon2id key derivation
- **In-Memory Only** - Keys are decrypted only at startup and held exclusively in memory
- **Memory Protection** - Uses `mlock` to prevent keys from being swapped to disk, `zeroize` ensures secure memory cleanup
- **gRPC Interface** - Modern, efficient API for all signing operations
- **Policy Engine** - Enforce transaction limits, address allowlists, rate limits, and 2FA requirements
- **Multi-Chain Support** - Native support for Ethereum (secp256k1) and Solana (Ed25519)
- **Container Ready** - Docker & Unix socket friendly with security-hardened deployment options

### 1.3 Use Cases

| Use Case | Description |
|----------|-------------|
| **Hot Wallet Management** | Secure signing for exchange hot wallets with policy controls |
| **Payment Processing** | Automated transaction signing with value limits |
| **DeFi Operations** | Programmatic interaction with smart contracts |
| **Custodial Services** | Multi-tenant key management with isolation |
| **Trading Bots** | High-frequency signing with rate limiting |

### 1.4 Security Philosophy

locksign follows the principle of **defense in depth**:

1. Keys never exist unencrypted on disk
2. Decrypted keys are locked in memory (no swap)
3. All key memory is zeroed on drop
4. Policy layer prevents unauthorized operations
5. Audit logging for all signing requests
6. No API endpoint ever returns private keys

---

## 2. Architecture

### 2.1 System Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Wallet App    │     │ Exchange Engine │     │  Payment System │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                          gRPC / TLS
                                 │
                    ┌────────────▼────────────┐
                    │      Auth Layer         │
                    │   (API Keys / Tokens)   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Policy Engine       │
                    │ • Address allowlists    │
                    │ • Value limits          │
                    │ • Rate limits           │
                    │ • 2FA requirements      │
                    │ • Time windows          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      Signer Core        │
                    │  Ethereum │ Solana      │
                    │  secp256k1│ Ed25519     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   In-Memory Key Store   │
                    │  • mlock (no swap)      │
                    │  • zeroize on drop      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Encrypted Storage     │
                    │  • AES-256-GCM          │
                    │  • Argon2id KDF         │
                    └─────────────────────────┘
```

### 2.2 Component Description

| Component | Purpose | Key Technologies |
|-----------|---------|------------------|
| **Auth Layer** | Request authentication and authorization | API keys, JWT tokens |
| **Policy Engine** | Enforce signing rules and limits | Configurable rules, real-time evaluation |
| **Signer Core** | Chain-specific signing logic | secp256k1, Ed25519 |
| **Memory Key Store** | Secure in-memory key storage | mlock, zeroize |
| **Encrypted Storage** | Persistent encrypted key files | AES-256-GCM, Argon2id |

### 2.3 Data Flow

1. **Startup**: Master password decrypts keys → loaded into locked memory
2. **Request**: gRPC request → Auth validation → Policy check → Sign → Response
3. **Shutdown**: All key memory zeroed → graceful termination

---

## 3. Installation & Setup

### 3.1 Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Rust | 1.75+ | Build toolchain |
| protoc | 3.x | Protocol Buffers compiler |
| OpenSSL | 1.1+ | TLS support |

**Install protoc:**

```bash
# Ubuntu/Debian
sudo apt install protobuf-compiler

# macOS
brew install protobuf

# Arch Linux
sudo pacman -S protobuf
```

### 3.2 Build from Source

```bash
# Clone repository
git clone https://github.com/yourorg/locksign.git
cd locksign

# Build release binary
cargo build --release

# Run tests
cargo test

# Binary location
./target/release/locksign
```

### 3.3 Quick Start

```bash
# 1. Create data directories
mkdir -p ./data/keys ./config

# 2. Set master password
export LOCKSIGN_MASTER_PASSWORD="your-secure-master-password"

# 3. Start the server
./target/release/locksign

# Server starts on 127.0.0.1:50051 by default
```

### 3.4 Verify Installation

```bash
# Check server is running
grpcurl -plaintext localhost:50051 list

# Expected output:
# locksign.ethereum.EthereumSigner
# locksign.solana.SolanaSigner
```

---

## 4. Configuration

### 4.1 Configuration File

Create `config.toml` in the working directory or at `/etc/locksign/config.toml`:

```toml
#
# locksign Configuration File
#

[server]
# Network binding
listen_addr = "127.0.0.1"
port = 50051

# Unix socket (alternative to TCP)
use_unix_socket = false
unix_socket = "/var/run/locksign/locksign.sock"

# TLS Configuration
tls_enabled = false
tls_cert = "/etc/locksign/server.crt"
tls_key = "/etc/locksign/server.key"

# Connection limits
max_connections = 100

[storage]
# Path to encrypted key files
keystore_path = "./data/keys"

# Encryption settings
encryption_algorithm = "aes-256-gcm"
kdf_iterations = 100000

[security]
# Memory protection
enable_mlock = true
disable_core_dumps = true

# Key rotation (0 = disabled)
max_key_age_days = 0

# Startup requirements
require_master_password = true

[policy]
# Enable policy enforcement
enabled = true

# Path to policy rules file
rules_path = "./config/policies.json"

# Default limits
default_daily_limit = 1000000000000000000  # 1 ETH in wei

[logging]
# Log level: trace, debug, info, warn, error
level = "info"

# Log format: pretty, json
format = "pretty"

# Log file (optional)
# file = "/var/log/locksign/locksign.log"
```

### 4.2 Environment Variables

All configuration options can be overridden via environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `LOCKSIGN_MASTER_PASSWORD` | Master decryption password | `"secure-password"` |
| `LOCKSIGN__SERVER__PORT` | Server port | `50052` |
| `LOCKSIGN__SERVER__LISTEN_ADDR` | Bind address | `"0.0.0.0"` |
| `LOCKSIGN__STORAGE__KEYSTORE_PATH` | Key storage path | `"/data/keys"` |
| `LOCKSIGN__POLICY__ENABLED` | Enable policies | `true` |
| `LOCKSIGN__LOGGING__LEVEL` | Log level | `"debug"` |

**Note:** Use double underscore `__` to separate nested config sections.

### 4.3 Configuration Priority

Configuration is loaded in the following order (later overrides earlier):

1. Built-in defaults
2. `/etc/locksign/config.toml`
3. `./config.toml`
4. Custom path via `--config` flag
5. Environment variables

---

## 5. Key Management

### 5.1 Key Storage Format

Keys are stored as encrypted JSON files in the keystore directory:

```json
{
  "version": 1,
  "key_id": "hot-wallet-1",
  "chain": "ethereum",
  "salt": "base64-encoded-16-byte-salt",
  "nonce": "base64-encoded-12-byte-nonce",
  "ciphertext": "base64-encoded-encrypted-key",
  "public_key": "0x742d35Cc6634C0532925a3b844Bc454e4438f44E",
  "created_at": 1704067200,
  "metadata": {
    "description": "Main hot wallet",
    "created_by": "admin"
  }
}
```

### 5.2 Encryption Details

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Algorithm** | AES-256-GCM | Authenticated encryption |
| **Key Derivation** | Argon2id | Memory-hard password hashing |
| **Memory** | 64 MB | Argon2 memory parameter |
| **Iterations** | 3 | Argon2 time parameter |
| **Parallelism** | 4 | Argon2 lanes |
| **Salt** | 16 bytes | Random per-key |
| **Nonce** | 12 bytes | Random per-encryption |

### 5.3 Supported Key Types

| Chain | Algorithm | Key Size | Public Key Format |
|-------|-----------|----------|-------------------|
| Ethereum | secp256k1 | 32 bytes | Checksummed address (0x...) |
| Solana | Ed25519 | 32 bytes (seed) | Base58 public key |

### 5.4 Key Operations

#### Import an Existing Key

```rust
use locksign::keystore::KeyLoader;

// Create loader
let loader = KeyLoader::new("./data/keys", memory_store)?;

// Import Ethereum key (32 bytes)
let eth_private_key = hex::decode("your-64-char-hex-key")?;
let info = loader.import_key(
    "my-eth-wallet",        // Unique key ID
    &eth_private_key,       // Private key bytes
    "ethereum",             // Chain type
    "master-password"       // Encryption password
)?;
println!("Imported: {} -> {}", info.key_id, info.public_key);

// Import Solana key (32 bytes seed)
let sol_seed = hex::decode("your-64-char-hex-seed")?;
let info = loader.import_key(
    "my-sol-wallet",
    &sol_seed,
    "solana",
    "master-password"
)?;
```

#### Generate a New Key

```rust
// Generate new Ethereum key
let info = loader.generate_key(
    "new-eth-wallet",
    "ethereum",
    "master-password"
)?;
println!("Generated ETH key: {}", info.public_key);

// Generate new Solana key  
let info = loader.generate_key(
    "new-sol-wallet",
    "solana",
    "master-password"
)?;
println!("Generated SOL key: {}", info.public_key);
```

#### List Keys

```rust
// List all loaded keys
let keys = loader.list_loaded_keys();
for key in keys {
    println!("{}: {} ({})", key.key_id, key.public_key, key.chain.as_str());
}
```

#### Delete a Key

```rust
// Remove from memory and delete encrypted file
loader.delete_key("old-wallet")?;
```

### 5.5 Key Backup & Recovery

**Backup Strategy:**

1. Backup the entire `keystore_path` directory
2. Store backups encrypted (they're already encrypted, but add another layer)
3. Keep backups in multiple secure locations
4. Test recovery periodically

**Recovery:**

1. Restore encrypted key files to `keystore_path`
2. Start locksign with the correct master password
3. Verify keys loaded correctly via API

⚠️ **Never backup or store unencrypted private keys!**

---

## 6. Policy Engine

### 6.1 Overview

The policy engine evaluates every signing request against configured rules before allowing the operation. This provides defense-in-depth even if other security measures are bypassed.

### 6.2 Policy Configuration File

Create `config/policies.json`:

```json
{
  "version": 1,
  "global_rules": [
    {
      "type": "rate_limit",
      "id": "global-rate-limit",
      "max_count": 1000,
      "period_seconds": 3600
    }
  ],
  "key_policies": {
    "hot-wallet": {
      "key_id": "hot-wallet",
      "enabled": true,
      "rules": [
        {
          "type": "value_limit",
          "id": "per-tx-limit",
          "max_value": 100000000000000000,
          "period_seconds": 0
        },
        {
          "type": "value_limit",
          "id": "daily-limit",
          "max_value": 1000000000000000000,
          "period_seconds": 86400
        },
        {
          "type": "allowlist",
          "id": "allowed-destinations",
          "addresses": [
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44E",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
          ],
          "allow_empty": false
        }
      ]
    },
    "cold-wallet": {
      "key_id": "cold-wallet",
      "enabled": true,
      "rules": [
        {
          "type": "require_2fa",
          "id": "always-2fa",
          "threshold": 0,
          "method": "totp"
        },
        {
          "type": "time_window",
          "id": "business-hours",
          "start_hour": 9,
          "start_minute": 0,
          "end_hour": 17,
          "end_minute": 0,
          "days": [1, 2, 3, 4, 5]
        }
      ]
    }
  }
}
```

### 6.3 Available Rule Types

#### Address Allowlist

Only allows transactions to pre-approved addresses.

```json
{
  "type": "allowlist",
  "id": "unique-rule-id",
  "addresses": [
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44E"
  ],
  "allow_empty": false
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `addresses` | array | List of allowed destination addresses |
| `allow_empty` | bool | If true, allow any address when list is empty |

#### Value Limit

Restricts transaction values per-transaction or over a time period.

```json
{
  "type": "value_limit",
  "id": "unique-rule-id",
  "max_value": 1000000000000000000,
  "period_seconds": 86400
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `max_value` | u128 | Maximum value in smallest unit (wei/lamports) |
| `period_seconds` | u64 | Time period (0 = per-transaction limit) |

**Common Values:**

| Amount | Wei Value |
|--------|-----------|
| 0.1 ETH | 100000000000000000 |
| 1 ETH | 1000000000000000000 |
| 10 ETH | 10000000000000000000 |

#### Rate Limit

Limits the number of signing operations over time.

```json
{
  "type": "rate_limit",
  "id": "unique-rule-id",
  "max_count": 100,
  "period_seconds": 3600
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `max_count` | u32 | Maximum operations allowed |
| `period_seconds` | u64 | Time window in seconds |

#### Require 2FA

Requires two-factor authentication for high-value operations.

```json
{
  "type": "require_2fa",
  "id": "unique-rule-id",
  "threshold": 500000000000000000,
  "method": "totp"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `threshold` | u128 | Value above which 2FA is required |
| `method` | string | 2FA method: "totp", "webauthn" |

#### Time Window

Restricts signing to specific hours and days.

```json
{
  "type": "time_window",
  "id": "unique-rule-id",
  "start_hour": 9,
  "start_minute": 0,
  "end_hour": 17,
  "end_minute": 0,
  "days": [1, 2, 3, 4, 5]
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `start_hour` | u8 | Start hour (0-23 UTC) |
| `start_minute` | u8 | Start minute (0-59) |
| `end_hour` | u8 | End hour (0-23 UTC) |
| `end_minute` | u8 | End minute (0-59) |
| `days` | array | Days of week (0=Sun, 6=Sat), empty=all days |

### 6.4 Policy Evaluation Order

1. Check if key is enabled
2. Evaluate global rules (all must pass)
3. Evaluate key-specific rules (all must pass)
4. Check 2FA requirement
5. Allow or deny request

---

## 7. gRPC API Reference

### 7.1 Service Overview

| Service | Description |
|---------|-------------|
| `EthereumSigner` | Ethereum signing operations |
| `SolanaSigner` | Solana signing operations |

### 7.2 Ethereum Service

#### SignMessage

Signs an arbitrary message using EIP-191 (personal_sign).

```protobuf
rpc SignMessage(EthSignMessageRequest) returns (Signature);

message EthSignMessageRequest {
  string key_id = 1;      // Key identifier
  string request_id = 2;  // Unique request ID for audit
  bytes message = 3;      // Raw message bytes
}

message Signature {
  bytes signature = 1;    // 65-byte signature (r || s || v)
  string public_key = 2;  // Signer address
}
```

**Example (grpcurl):**

```bash
grpcurl -plaintext -d '{
  "key_id": "my-eth-wallet",
  "request_id": "req-001",
  "message": "SGVsbG8gV29ybGQ="
}' localhost:50051 locksign.ethereum.EthereumSigner/SignMessage
```

#### SignTransaction

Signs a raw Ethereum transaction.

```protobuf
rpc SignTransaction(EthSignTransactionRequest) returns (EthSignTransactionResponse);

message EthSignTransactionRequest {
  string key_id = 1;
  string request_id = 2;
  oneof transaction {
    EthTransaction legacy_tx = 3;
    EthEIP1559Transaction eip1559_tx = 4;
  }
}

message EthSignTransactionResponse {
  bytes signed_transaction = 1;  // RLP-encoded signed tx
  string tx_hash = 2;            // Transaction hash
  uint32 v = 3;
  bytes r = 4;
  bytes s = 5;
}
```

#### GetAddress

Returns the Ethereum address for a key.

```protobuf
rpc GetAddress(EthGetAddressRequest) returns (EthGetAddressResponse);

message EthGetAddressRequest {
  string key_id = 1;
}

message EthGetAddressResponse {
  string address = 1;      // Checksummed address (0x...)
  string public_key = 2;   // Uncompressed public key
}
```

### 7.3 Solana Service

#### SignMessage

Signs an arbitrary message.

```protobuf
rpc SignMessage(SolSignMessageRequest) returns (Signature);

message SolSignMessageRequest {
  string key_id = 1;
  string request_id = 2;
  bytes message = 3;
}
```

#### SignTransaction

Signs a serialized Solana transaction.

```protobuf
rpc SignTransaction(SolSignTransactionRequest) returns (SolSignTransactionResponse);

message SolSignTransactionRequest {
  string key_id = 1;
  string request_id = 2;
  bytes transaction = 3;        // Serialized transaction message
  string recent_blockhash = 4;  // Optional override
}

message SolSignTransactionResponse {
  bytes signed_transaction = 1;
  bytes signature = 2;          // 64-byte signature
}
```

#### GetPublicKey

Returns the Solana public key for a key.

```protobuf
rpc GetPublicKey(SolGetPublicKeyRequest) returns (SolGetPublicKeyResponse);

message SolGetPublicKeyRequest {
  string key_id = 1;
}

message SolGetPublicKeyResponse {
  string public_key = 1;       // Base58-encoded
  bytes public_key_bytes = 2;  // Raw 32 bytes
}
```

### 7.4 Error Codes

| Code | Status | Description |
|------|--------|-------------|
| 3 | `INVALID_ARGUMENT` | Invalid request parameters |
| 5 | `NOT_FOUND` | Key not found |
| 6 | `ALREADY_EXISTS` | Key already exists |
| 7 | `PERMISSION_DENIED` | Policy violation |
| 9 | `FAILED_PRECONDITION` | Key is disabled |
| 12 | `UNIMPLEMENTED` | Feature not implemented |
| 13 | `INTERNAL` | Internal server error |
| 16 | `UNAUTHENTICATED` | Authentication failed |

### 7.5 Client Examples

#### Rust Client

```rust
use locksign::proto::ethereum::ethereum_signer_client::EthereumSignerClient;
use locksign::proto::ethereum::EthSignMessageRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to server
    let mut client = EthereumSignerClient::connect("http://127.0.0.1:50051").await?;

    // Sign a message
    let request = tonic::Request::new(EthSignMessageRequest {
        key_id: "my-eth-wallet".to_string(),
        request_id: uuid::Uuid::new_v4().to_string(),
        message: b"Hello, Ethereum!".to_vec(),
    });

    let response = client.sign_message(request).await?;
    let sig = response.into_inner();
    
    println!("Signature: 0x{}", hex::encode(&sig.signature));
    println!("Signer: {}", sig.public_key);

    Ok(())
}
```

#### Python Client

```python
import grpc
from locksign import ethereum_pb2, ethereum_pb2_grpc

# Connect
channel = grpc.insecure_channel('localhost:50051')
stub = ethereum_pb2_grpc.EthereumSignerStub(channel)

# Sign message
request = ethereum_pb2.EthSignMessageRequest(
    key_id="my-eth-wallet",
    request_id="req-001",
    message=b"Hello, Ethereum!"
)

response = stub.SignMessage(request)
print(f"Signature: 0x{response.signature.hex()}")
print(f"Signer: {response.public_key}")
```

#### Node.js Client

```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const packageDef = protoLoader.loadSync('proto/ethereum.proto');
const proto = grpc.loadPackageDefinition(packageDef);

const client = new proto.locksign.ethereum.EthereumSigner(
  'localhost:50051',
  grpc.credentials.createInsecure()
);

client.SignMessage({
  key_id: 'my-eth-wallet',
  request_id: 'req-001',
  message: Buffer.from('Hello, Ethereum!')
}, (err, response) => {
  if (err) throw err;
  console.log('Signature:', response.signature.toString('hex'));
  console.log('Signer:', response.public_key);
});
```

---

## 8. Security Considerations

### 8.1 Memory Protection

#### mlock

Memory containing decrypted keys is locked using `mlock()` system call to prevent swapping to disk.

```rust
// Keys are automatically locked when loaded
let locked_memory = LockedMemory::from_vec(key_bytes)?;
// Memory is unlocked and zeroed on drop
```

**Requirements:**
- Linux: May need `CAP_IPC_LOCK` capability or increased `RLIMIT_MEMLOCK`
- Docker: Add `--cap-add=IPC_LOCK` or increase memlock limit

#### Zeroize

All sensitive memory is zeroed when no longer needed:

```rust
// SecureBytes automatically zeros on drop
let key = SecureBytes::new(private_key_vec);
// When `key` goes out of scope, memory is zeroed
```

### 8.2 Core Dump Prevention

Core dumps are disabled at startup to prevent key leakage:

```rust
// Automatically called at startup
setup_memory_protection()?;
// Sets RLIMIT_CORE to 0
```

### 8.3 Network Security

#### TLS Configuration

Always enable TLS in production:

```toml
[server]
tls_enabled = true
tls_cert = "/etc/locksign/server.crt"
tls_key = "/etc/locksign/server.key"
```

**Generate self-signed certificate (testing only):**

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

#### Unix Sockets

For local applications, prefer Unix sockets over TCP:

```toml
[server]
use_unix_socket = true
unix_socket = "/var/run/locksign/locksign.sock"
```

### 8.4 Best Practices Checklist

| Practice | Importance | Description |
|----------|------------|-------------|
| ✅ Enable TLS | Critical | Encrypt all network traffic |
| ✅ Use Unix sockets | High | For local apps, avoid network exposure |
| ✅ Enable mlock | High | Prevent key swapping |
| ✅ Disable core dumps | High | Prevent key leakage |
| ✅ Configure policies | High | Limit blast radius |
| ✅ Use API authentication | High | Control access |
| ✅ Enable audit logging | Medium | Track all operations |
| ✅ Rotate keys | Medium | Limit key exposure time |
| ✅ Backup encrypted keys | Medium | Disaster recovery |
| ✅ Run as non-root | Medium | Principle of least privilege |

### 8.5 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Network eavesdropping** | TLS encryption |
| **Disk theft** | AES-256-GCM encryption |
| **Memory dump** | mlock, zeroize, no core dumps |
| **Unauthorized signing** | Policy engine, authentication |
| **Insider threat** | Audit logging, 2FA |
| **Key exhaustion** | Rate limiting |
| **Phishing** | Address allowlists |

---

## 9. Docker Deployment

### 9.1 Dockerfile

```dockerfile
# Build stage
FROM rust:1.75-alpine AS builder
RUN apk add --no-cache musl-dev protobuf-dev openssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates libgcc

# Create non-root user
RUN addgroup -g 1000 locksign && \
    adduser -D -u 1000 -G locksign locksign

# Copy binary
COPY --from=builder /app/target/release/locksign /usr/local/bin/

# Create directories
RUN mkdir -p /data/keys /etc/locksign && \
    chown -R locksign:locksign /data /etc/locksign

USER locksign
WORKDIR /data

EXPOSE 50051

ENTRYPOINT ["locksign"]
```

### 9.2 Docker Compose

```yaml
version: '3.8'

services:
  locksign:
    build: .
    container_name: locksign
    restart: unless-stopped
    
    # Security hardening
    cap_drop:
      - ALL
    cap_add:
      - IPC_LOCK  # For mlock
    read_only: true
    security_opt:
      - no-new-privileges:true
    
    # Environment
    environment:
      - LOCKSIGN_MASTER_PASSWORD=${MASTER_PASSWORD}
      - LOCKSIGN__SERVER__PORT=50051
      - LOCKSIGN__LOGGING__LEVEL=info
    
    # Volumes
    volumes:
      - ./data/keys:/data/keys:ro
      - ./config:/etc/locksign:ro
      - locksign-tmp:/tmp
    
    # Network
    ports:
      - "127.0.0.1:50051:50051"
    
    # Resources
    deploy:
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 64M
    
    # Health check
    healthcheck:
      test: ["CMD", "grpcurl", "-plaintext", "localhost:50051", "list"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  locksign-tmp:
```

### 9.3 Security Flags Explained

| Flag | Purpose |
|------|---------|
| `cap_drop: ALL` | Remove all Linux capabilities |
| `cap_add: IPC_LOCK` | Allow memory locking |
| `read_only: true` | Read-only root filesystem |
| `no-new-privileges` | Prevent privilege escalation |
| `user: 1000:1000` | Run as non-root |

### 9.4 Production Deployment

```bash
# 1. Create directories
mkdir -p ./data/keys ./config

# 2. Set password securely
export MASTER_PASSWORD=$(cat /path/to/secure/password)

# 3. Start with docker-compose
docker-compose up -d

# 4. Check logs
docker-compose logs -f locksign

# 5. Verify health
docker-compose exec locksign grpcurl -plaintext localhost:50051 list
```

---

## 10. Troubleshooting

### 10.1 Common Issues

#### Server won't start: "LOCKSIGN_MASTER_PASSWORD not set"

**Cause:** Master password environment variable is missing.

**Solution:**
```bash
export LOCKSIGN_MASTER_PASSWORD="your-password"
```

#### "Failed to lock memory"

**Cause:** Insufficient permissions for mlock.

**Solutions:**

1. Increase memlock limit:
```bash
# Add to /etc/security/limits.conf
locksign soft memlock unlimited
locksign hard memlock unlimited
```

2. Or run with capability:
```bash
sudo setcap cap_ipc_lock=+ep ./locksign
```

3. In Docker, add:
```yaml
cap_add:
  - IPC_LOCK
```

#### "Key not found"

**Cause:** Key ID doesn't exist or wasn't loaded.

**Solutions:**
1. Check key files exist in keystore_path
2. Verify master password is correct
3. Check server logs for load errors

#### "Policy violation"

**Cause:** Request blocked by policy rules.

**Solutions:**
1. Check policy configuration
2. Verify address is in allowlist
3. Check value/rate limits
4. Ensure within time window

### 10.2 Debug Mode

Enable debug logging:

```bash
export RUST_LOG=debug
./locksign
```

Or in config:
```toml
[logging]
level = "debug"
```

### 10.3 Health Check

```bash
# Check if server is responding
grpcurl -plaintext localhost:50051 list

# Get server health (if implemented)
grpcurl -plaintext localhost:50051 locksign.health.Health/Check
```

---

## 11. Project Structure

```
locksign/
├── Cargo.toml              # Dependencies and metadata
├── build.rs                # Protobuf compilation
├── README.md               # Quick start guide
├── proto/                  # Protocol Buffer definitions
│   ├── common.proto        # Shared types
│   ├── ethereum.proto      # Ethereum service
│   └── solana.proto        # Solana service
└── src/
    ├── main.rs             # Entry point, server bootstrap
    ├── errors.rs           # Error types and handling
    ├── config/             
    │   └── mod.rs          # Configuration loading
    ├── api/                
    │   ├── mod.rs          # API module
    │   ├── grpc.rs         # gRPC service implementations
    │   └── auth.rs         # Authentication middleware
    ├── policy/             
    │   ├── mod.rs          # Policy module
    │   ├── engine.rs       # Policy evaluation engine
    │   └── rules.rs        # Rule type definitions
    ├── keystore/           
    │   ├── mod.rs          # Keystore module
    │   ├── encrypted.rs    # Encrypted file storage
    │   ├── memory.rs       # In-memory key store
    │   └── loader.rs       # Key loading utilities
    ├── signer/             
    │   ├── mod.rs          # Signer module
    │   ├── ethereum.rs     # Ethereum signing
    │   └── solana.rs       # Solana signing
    ├── crypto/             
    │   ├── mod.rs          # Crypto module
    │   ├── eth.rs          # secp256k1 operations
    │   └── sol.rs          # Ed25519 operations
    └── security/           
        ├── mod.rs          # Security module
        ├── zeroize.rs      # Secure memory zeroing
        └── mlock.rs        # Memory locking
```

---

## 12. Roadmap

### Phase 1: Core (Current)
- ✅ Encrypted key storage
- ✅ In-memory key management
- ✅ Ethereum signing (secp256k1)
- ✅ Solana signing (Ed25519)
- ✅ Policy engine
- ✅ gRPC API

### Phase 2: Wallet Service
- [ ] Multi-account management
- [ ] Balance tracking
- [ ] Transaction history
- [ ] HD wallet derivation

### Phase 3: Exchange Integration
- [ ] Order signing
- [ ] Batch operations
- [ ] Webhook notifications
- [ ] Audit log export

### Phase 4: Multi-Tenant
- [ ] Tenant isolation
- [ ] RBAC (Role-Based Access Control)
- [ ] API key management
- [ ] Usage quotas

### Phase 5: Advanced Security
- [ ] HSM integration
- [ ] MPC (Multi-Party Computation)
- [ ] Threshold signatures
- [ ] Hardware key support

---

## License

MIT License - See LICENSE file for details.

---

## Support

- **GitHub Issues:** Report bugs and feature requests


---

*This documentation is for locksign version 0.1.0*