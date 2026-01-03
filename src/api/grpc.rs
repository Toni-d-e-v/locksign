//! gRPC service implementations
//!
//! Implements the gRPC services defined in the proto files.

use crate::api::auth::{auth_error_to_status, AuthService};
use crate::errors::LockSignError;
use crate::keystore::{KeyLoader, MemoryKeyStore};
use crate::policy::PolicyEngine;
use crate::signer::{EthereumSigner, SolanaSigner};
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};
use tracing::{error, info};

// Include generated protobuf code
pub mod proto {
    pub mod common {
        tonic::include_proto!("locksign.common");
    }

    pub mod ethereum {
        tonic::include_proto!("locksign.ethereum");
    }

    pub mod solana {
        tonic::include_proto!("locksign.solana");
    }
}

use proto::common::{HealthRequest, HealthResponse, KeyInfo, ListKeysRequest, ListKeysResponse};
use proto::ethereum::{
    ethereum_signer_server::EthereumSigner as EthereumSignerTrait, EthGetAddressRequest,
    EthGetAddressResponse, EthSignMessageRequest, EthSignTransactionRequest,
    EthSignTransactionResponse, EthSignTypedDataRequest,
};
use proto::solana::{
    solana_signer_server::SolanaSigner as SolanaSignerTrait, SolGetPublicKeyRequest,
    SolGetPublicKeyResponse, SolPartialSignRequest, SolPartialSignResponse,
    SolSignMessageRequest, SolSignTransactionRequest, SolSignTransactionResponse,
};

/// Shared application state
pub struct AppState {
    pub key_store: Arc<MemoryKeyStore>,
    pub key_loader: Arc<KeyLoader>,
    pub policy_engine: Arc<PolicyEngine>,
    pub auth_service: Arc<AuthService>,
    pub eth_signer: EthereumSigner,
    pub sol_signer: SolanaSigner,
    pub start_time: Instant,
}

impl AppState {
    pub fn new(
        key_store: Arc<MemoryKeyStore>,
        key_loader: Arc<KeyLoader>,
        policy_engine: Arc<PolicyEngine>,
        auth_service: Arc<AuthService>,
    ) -> Self {
        let eth_signer = EthereumSigner::new(key_store.clone(), policy_engine.clone());
        let sol_signer = SolanaSigner::new(key_store.clone(), policy_engine.clone());

        Self {
            key_store,
            key_loader,
            policy_engine,
            auth_service,
            eth_signer,
            sol_signer,
            start_time: Instant::now(),
        }
    }
}

/// Ethereum gRPC service implementation
pub struct EthereumSignerService {
    state: Arc<AppState>,
}

impl EthereumSignerService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    fn validate_auth<T>(&self, request: &Request<T>) -> Result<(), Status> {
        self.state
            .auth_service
            .validate_request(request)
            .map_err(auth_error_to_status)?;
        Ok(())
    }
}

#[tonic::async_trait]
impl EthereumSignerTrait for EthereumSignerService {
    async fn sign_transaction(
        &self,
        request: Request<EthSignTransactionRequest>,
    ) -> Result<Response<EthSignTransactionResponse>, Status> {
        self.validate_auth(&request)?;

        let req = request.into_inner();
        let key_id = &req.key_id;
        let request_id = &req.request_id;

        info!("ETH SignTransaction request: key={}, req={}", key_id, request_id);

        // TODO: Parse transaction from request and sign
        // For now, return unimplemented
        Err(Status::unimplemented(
            "Transaction signing not yet implemented",
        ))
    }

    async fn sign_message(
        &self,
        request: Request<EthSignMessageRequest>,
    ) -> Result<Response<proto::common::Signature>, Status> {
        self.validate_auth(&request)?;

        let req = request.into_inner();
        let key_id = &req.key_id;
        let request_id = &req.request_id;

        info!("ETH SignMessage request: key={}, req={}", key_id, request_id);

        let signature = self
            .state
            .eth_signer
            .sign_message(key_id, request_id, &req.message)
            .map_err(|e| Status::from(e))?;

        let pubkey = self
            .state
            .eth_signer
            .get_address(key_id)
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(proto::common::Signature {
            signature: signature.to_bytes().to_vec(),
            public_key: pubkey,
        }))
    }

    async fn sign_typed_data(
        &self,
        request: Request<EthSignTypedDataRequest>,
    ) -> Result<Response<proto::common::Signature>, Status> {
        self.validate_auth(&request)?;

        // TODO: Implement EIP-712 typed data signing
        Err(Status::unimplemented("EIP-712 signing not yet implemented"))
    }

    async fn get_address(
        &self,
        request: Request<EthGetAddressRequest>,
    ) -> Result<Response<EthGetAddressResponse>, Status> {
        self.validate_auth(&request)?;

        let req = request.into_inner();
        let key_id = &req.key_id;

        let address = self
            .state
            .eth_signer
            .get_address(key_id)
            .map_err(|e| Status::from(e))?;

        // Get uncompressed public key
        let key_info = self
            .state
            .key_store
            .get_key_info(key_id)
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(EthGetAddressResponse {
            address,
            public_key: key_info.public_key,
        }))
    }
}

/// Solana gRPC service implementation
pub struct SolanaSignerService {
    state: Arc<AppState>,
}

impl SolanaSignerService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    fn validate_auth<T>(&self, request: &Request<T>) -> Result<(), Status> {
        self.state
            .auth_service
            .validate_request(request)
            .map_err(auth_error_to_status)?;
        Ok(())
    }
}

#[tonic::async_trait]
impl SolanaSignerTrait for SolanaSignerService {
    async fn sign_transaction(
        &self,
        request: Request<SolSignTransactionRequest>,
    ) -> Result<Response<SolSignTransactionResponse>, Status> {
        self.validate_auth(&request)?;

        let req = request.into_inner();
        let key_id = &req.key_id;
        let request_id = &req.request_id;

        info!("SOL SignTransaction request: key={}, req={}", key_id, request_id);

        let signature = self
            .state
            .sol_signer
            .sign_transaction(key_id, request_id, &req.transaction)
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(SolSignTransactionResponse {
            signed_transaction: req.transaction, // In real impl, we'd insert the signature
            signature: signature.bytes.to_vec(),
        }))
    }

    async fn sign_message(
        &self,
        request: Request<SolSignMessageRequest>,
    ) -> Result<Response<proto::common::Signature>, Status> {
        self.validate_auth(&request)?;

        let req = request.into_inner();
        let key_id = &req.key_id;
        let request_id = &req.request_id;

        info!("SOL SignMessage request: key={}, req={}", key_id, request_id);

        let signature = self
            .state
            .sol_signer
            .sign_message(key_id, request_id, &req.message)
            .map_err(|e| Status::from(e))?;

        let pubkey = self
            .state
            .sol_signer
            .get_public_key(key_id)
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(proto::common::Signature {
            signature: signature.bytes.to_vec(),
            public_key: pubkey,
        }))
    }

    async fn get_public_key(
        &self,
        request: Request<SolGetPublicKeyRequest>,
    ) -> Result<Response<SolGetPublicKeyResponse>, Status> {
        self.validate_auth(&request)?;

        let req = request.into_inner();
        let key_id = &req.key_id;

        let pubkey = self
            .state
            .sol_signer
            .get_public_key(key_id)
            .map_err(|e| Status::from(e))?;

        let pubkey_bytes = self
            .state
            .sol_signer
            .get_public_key_bytes(key_id)
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(SolGetPublicKeyResponse {
            public_key: pubkey,
            public_key_bytes: pubkey_bytes.to_vec(),
        }))
    }

    async fn partial_sign(
        &self,
        request: Request<SolPartialSignRequest>,
    ) -> Result<Response<SolPartialSignResponse>, Status> {
        self.validate_auth(&request)?;

        let req = request.into_inner();
        let key_id = &req.key_id;
        let request_id = &req.request_id;

        let signature = self
            .state
            .sol_signer
            .partial_sign(key_id, request_id, &req.transaction)
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(SolPartialSignResponse {
            transaction: req.transaction,
            signature: signature.bytes.to_vec(),
        }))
    }
}

/// Health check service
pub struct HealthService {
    state: Arc<AppState>,
}

impl HealthService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub fn check_health(&self) -> HealthResponse {
        let uptime = self.state.start_time.elapsed().as_secs() as i64;
        let keys_loaded = self.state.key_store.key_count() as i32;

        HealthResponse {
            healthy: true,
            keys_loaded,
            uptime_seconds: uptime,
        }
    }
}

/// Key management service
pub struct KeyManagementService {
    state: Arc<AppState>,
}

impl KeyManagementService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub fn list_keys(&self) -> ListKeysResponse {
        let keys = self.state.key_store.list_keys();

        let key_infos: Vec<KeyInfo> = keys
            .into_iter()
            .map(|k| KeyInfo {
                key_id: k.key_id,
                public_key: k.public_key,
                chain: k.chain.as_str().to_string(),
                created_at: k.created_at,
                enabled: k.enabled,
            })
            .collect();

        ListKeysResponse { keys: key_infos }
    }
}
