# 🔐 locksign

**Secure, in-memory blockchain signing service for Ethereum & Solana**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)

---

## Overview

`locksign` is an open-source, self-hosted signing service designed for security-first blockchain operations:

- 🔒 **Encrypted at Rest** - Private keys are AES-256-GCM encrypted on disk
- 🧠 **In-Memory Only** - Keys decrypted only at startup, never written unencrypted
- 🛡️ **Memory Protection** - Uses `mlock` to prevent swapping, `zeroize` on drop
- 📡 **gRPC Interface** - Modern, efficient API for signing operations
- 📋 **Policy Engine** - Enforce limits, allowlists, rate limits, and 2FA
- 🔗 **Multi-Chain** - Supports Ethereum (secp256k1) and Solana (Ed25519)
- 🐳 **Container Ready** - Docker & Unix socket friendly

---

## Architecture

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

---

## Quick Start

### Prerequisites

- **Rust** 1.75 or later
- **protoc** (Protocol Buffers compiler)

```bash
# Ubuntu/Debian
sudo apt install protobuf-compiler

# macOS
brew install protobuf

# Arch Linux
sudo pacman -S protobuf
```

### Build

```bash
# Clone the repository
git clone https://github.com/yourorg/locksign.git
cd locksign

# Build in release mode
cargo build --release

# Run tests
cargo test
```

### Run

```bash
# Set the master password (required to decrypt keys)
export LOCKSIGN_MASTER_PASSWORD="your-secure-master-password"

# Start the server
./target/release/locksign

# Or with a custom config file
./target/release/locksign --config /etc/locksign/config.toml
```

The server will start on `127.0.0.1:50051` by default.

---

## Configuration

Create a `config.toml` file:

```toml
[server]
listen_addr = "127.0.0.1"
port = 50051
use_unix_socket = false
unix_socket = "/var/run/locksign/locksign.sock"
tls_enabled = false
# tls_cert = "/etc/locksign/server.crt"
# tls_key = "/etc/locksign/server.key"
max_connections = 100

[storage]
keystore_path = "./data/keys"
encryption_algorithm = "aes-256-gcm"
kdf_iterations = 100000

[security]
enable_mlock = true
disable_core_dumps = true
max_key_age_days = 0  # 0 = no limit
require_master_password = true

[policy]
enabled = true
rules_path = "./config/policies.json"
default_daily_limit = 1000000000000000000  # 1 ETH in wei

[logging]
level = "info"  # trace, debug, info, warn, error
format = "pretty"  # pretty, json
# file = "/var/log/locksign/locksign.log"
```

### Environment Variables

All config options can be set via environment variables with `LOCKSIGN__` prefix:

```bash
export LOCKSIGN__SERVER__PORT=50052
export LOCKSIGN__STORAGE__KEYSTORE_PATH=/data/keys
export LOCKSIGN__POLICY__ENABLED=true
export LOCKSIGN_MASTER_PASSWORD="your-password"
```

---

## Key Management

### Encrypted Key Format

Keys are stored as JSON files with AES-256-GCM encryption:

```json
{
  "version": 1,
  "key_id": "hot-wallet-1",
  "chain": "ethereum",
  "salt": "base64-encoded-salt",
  "nonce": "base64-encoded-nonce",
  "ciphertext": "base64-encoded-encrypted-key",
  "public_key": "0x742d35Cc6634C0532925a3b844Bc454e4438f44E",
  "created_at": 1704067200,
  "metadata": {}
}
```

### Import a Key (Programmatic)

```rust
use locksign::keystore::KeyLoader;

let loader = KeyLoader::new("./data/keys", memory_store)?;

// Import an Ethereum private key (32 bytes)
let eth_key = hex::decode("your-private-key-hex")?;
loader.import_key(
    "my-eth-wallet",      // key ID
    &eth_key,             // private key bytes
    "ethereum",           // chain type
    "master-password"     // encryption password
)?;

// Import a Solana private key (32 bytes seed)
let sol_key = hex::decode("your-solana-seed-hex")?;
loader.import_key(
    "my-sol-wallet",
    &sol_key,
    "solana",
    "master-password"
)?;
```

### Generate a New Key

```rust
// Generate a new Ethereum key
let info = loader.generate_key("new-eth-key", "ethereum", "master-password")?;
println!("Created key with address: {}", info.public_key);

// Generate a new Solana key
let info = loader.generate_key("new-sol-key", "solana", "master-password")?;
println!("Created key with pubkey: {}", info.public_key);
```

---

## Policy Engine

The policy engine enforces rules before any signing operation.

### Policy Configuration

Create a `policies.json` file:

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
        },
        {
          "type": "rate_limit",
          "id": "tx-rate-limit",
          "max_count": 100,
          "period_seconds": 3600
        }
      ]
    },
    "cold-wallet": {
      "key_id": "cold-wallet",
      "enabled": true,
      "rules": [
        {
          "type": "require_2fa",
          "id": "2fa-all",
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

### Available Policy Rules

| Rule Type | Description | Parameters |
|-----------|-------------|------------|
| `allowlist` | Only allow transactions to specific addresses | `addresses`, `allow_empty` |
| `value_limit` | Limit max value per transaction or time period | `max_value`, `period_seconds` (0 = per-tx) |
| `rate_limit` | Limit number of signing operations | `max_count`, `period_seconds` |
| `require_2fa` | Require 2FA for values above threshold | `threshold`, `method` |
| `time_window` | Only allow signing during specific hours | `start_hour`, `end_hour`, `days` |

---

## gRPC API

### Service Definitions

#### Ethereum Signer

```protobuf
service EthereumSigner {
  // Sign a raw Ethereum transaction
  rpc SignTransaction(EthSignTransactionRequest) returns (EthSignTransactionResponse);
  
  // Sign an arbitrary message (EIP-191 personal sign)
  rpc SignMessage(EthSignMessageRequest) returns (Signature);
  
  // Sign typed data (EIP-712)
  rpc SignTypedData(EthSignTypedDataRequest) returns (Signature);
  
  // Get the Ethereum address for a key
  rpc GetAddress(EthGetAddressRequest) returns (EthGetAddressResponse);
}
```

#### Solana Signer

```protobuf
service SolanaSigner {
  // Sign a Solana transaction
  rpc SignTransaction(SolSignTransactionRequest) returns (SolSignTransactionResponse);
  
  // Sign an arbitrary message
  rpc SignMessage(SolSignMessageRequest) returns (Signature);
  
  // Get the Solana public key for a key
  rpc GetPublicKey(SolGetPublicKeyRequest) returns (SolGetPublicKeyResponse);
  
  // Partially sign a transaction (multi-sig)
  rpc PartialSign(SolPartialSignRequest) returns (SolPartialSignResponse);
}
```

### Client Example (Rust)

```rust
use locksign::proto::ethereum::ethereum_signer_client::EthereumSignerClient;
use locksign::proto::ethereum::EthSignMessageRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = EthereumSignerClient::connect("http://127.0.0.1:50051").await?;

    let request = tonic::Request::new(EthSignMessageRequest {
        key_id: "my-eth-wallet".to_string(),
        request_id: "req-123".to_string(),
        message: b"Hello, Ethereum!".to_vec(),
    });

    let response = client.sign_message(request).await?;
    let signature = response.into_inner();
    
    println!("Signature: 0x{}", hex::encode(&signature.signature));
    println!("Signer: {}", signature.public_key);

    Ok(())
}
```

### Client Example (Python with grpcio)

```python
import grpc
from locksign import ethereum_pb2, ethereum_pb2_grpc

channel = grpc.insecure_channel('localhost:50051')
stub = ethereum_pb2_grpc.EthereumSignerStub(channel)

request = ethereum_pb2.EthSignMessageRequest(
    key_id="my-eth-wallet",
    request_id="req-123",
    message=b"Hello, Ethereum!"
)

response = stub.SignMessage(request)
print(f"Signature: 0x{response.signature.hex()}")
print(f"Signer: {response.public_key}")
```

---

## Docker Deployment

### Dockerfile

```dockerfile
FROM rust:1.75-alpine AS builder
RUN apk add --no-cache musl-dev protobuf-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/locksign /usr/local/bin/
RUN adduser -D -u 1000 locksign
USER locksign
EXPOSE 50051
CMD ["locksign"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  locksign:
    build: .
    container_name: locksign
    restart: unless-stopped
    cap_drop:
      - ALL
    read_only: true
    security_opt:
      - no-new-privileges:true
    environment:
      - LOCKSIGN_MASTER_PASSWORD=${MASTER_PASSWORD}
      - LOCKSIGN__SERVER__PORT=50051
      - LOCKSIGN__LOGGING__LEVEL=info
    volumes:
      - ./data/keys:/data/keys:ro
      - ./config:/etc/locksign:ro
    ports:
      - "127.0.0.1:50051:50051"
    tmpfs:
      - /tmp:size=10M,mode=1777
```

### Run with Docker

```bash
# Build
docker build -t locksign .

# Run with security hardening
docker run -d \
  --name locksign \
  --cap-drop=ALL \
  --read-only \
  --security-opt=no-new-privileges \
  -e LOCKSIGN_MASTER_PASSWORD="your-password" \
  -v $(pwd)/data/keys:/data/keys:ro \
  -v $(pwd)/config:/etc/locksign:ro \
  -p 127.0.0.1:50051:50051 \
  locksign
```

---

## Security Considerations

### Memory Protection

- **mlock**: Key memory is locked to prevent swapping to disk
- **zeroize**: All sensitive memory is zeroed on drop
- **No core dumps**: Core dumps are disabled to prevent key leakage

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: Argon2id with 64MB memory, 3 iterations
- **Unique Nonces**: Random 12-byte nonces for each encryption

### Best Practices

1. **Never expose raw private keys** - locksign never returns private keys via API
2. **Use TLS** - Enable TLS for production gRPC connections
3. **Use Unix sockets** - For local apps, prefer Unix sockets over TCP
4. **Rotate keys** - Set `max_key_age_days` to enforce key rotation
5. **Limit access** - Use API keys and permissions
6. **Monitor** - Enable audit logging for all signing operations
7. **Backup encrypted keys** - Keep encrypted backups, never unencrypted

### Docker Security Flags

Always run with these flags in production:

```bash
--cap-drop=ALL          # Drop all capabilities
--read-only             # Read-only filesystem
--no-new-privileges     # Prevent privilege escalation
--user 1000:1000        # Run as non-root
```

---

## Project Structure

```
locksign/
├── Cargo.toml              # Dependencies
├── build.rs                # Protobuf compilation
├── proto/                  # Protocol definitions
│   ├── common.proto        # Shared types
│   ├── ethereum.proto      # Ethereum service
│   └── solana.proto        # Solana service
└── src/
    ├── main.rs             # Entry point, server bootstrap
    ├── errors.rs           # Error types
    ├── config/             # Configuration management
    │   └── mod.rs
    ├── api/                # gRPC services
    │   ├── mod.rs
    │   ├── grpc.rs         # Service implementations
    │   └── auth.rs         # Authentication
    ├── policy/             # Policy engine
    │   ├── mod.rs
    │   ├── engine.rs       # Policy evaluation
    │   └── rules.rs        # Rule definitions
    ├── keystore/           # Key management
    │   ├── mod.rs
    │   ├── encrypted.rs    # Encrypted storage
    │   ├── memory.rs       # In-memory store
    │   └── loader.rs       # Key loading
    ├── signer/             # Chain signers
    │   ├── mod.rs
    │   ├── ethereum.rs     # ETH signing
    │   └── solana.rs       # SOL signing
    ├── crypto/             # Cryptographic utilities
    │   ├── mod.rs
    │   ├── eth.rs          # secp256k1
    │   └── sol.rs          # Ed25519
    └── security/           # Security utilities
        ├── mod.rs
        ├── zeroize.rs      # Memory zeroing
        └── mlock.rs        # Memory locking
```

---

## Roadmap

- [x] **Phase 1**: Core signer + policy engine (current)
- [ ] **Phase 2**: Wallet service (multi-account, balance tracking)
- [ ] **Phase 3**: Exchange engine integration
- [ ] **Phase 4**: Multi-tenant / RBAC
- [ ] **Phase 5**: HSM / MPC integration

---



```bash
# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run

# Format code
cargo fmt

# Lint
cargo clippy
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with:
- [tonic](https://github.com/hyperium/tonic) - gRPC framework
- [k256](https://github.com/RustCrypto/elliptic-curves) - secp256k1
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) - Ed25519
- [aes-gcm](https://github.com/RustCrypto/AEADs) - Authenticated encryption
- [argon2](https://github.com/RustCrypto/password-hashes) - Key derivation
- [zeroize](https://github.com/RustCrypto/utils) - Secure memory handling