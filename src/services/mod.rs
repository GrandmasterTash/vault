mod create_policy;
mod hash_password;
mod validate_password;

use super::grpc::*;
use futures::Stream;
use mongodb::Database;
use serde_json::Value;
use tracing::instrument;
use parking_lot::RwLock;
use std::{pin::Pin, sync::Arc};
use crate::utils::errors::VaultError;
use tonic::{Request, Response, Status, Streaming};
use super::grpc::password_service_server::PasswordService;
use crate::{model::policy::PolicyDB, utils::config::Configuration};

#[cfg(feature = "kafka")]
use rdkafka::producer::FutureProducer;

///
/// The context is available to all gRPC service endpoints and gives them access to the DB, Kafka, config, etc.
///
pub struct ServiceContext {
    db: Database,
    active_policy: Arc<RwLock<PolicyDB>>,

    #[allow(dead_code)] // TODO: remove when kafka added as default feature?
    config: Configuration,

    #[cfg(feature = "kafka")]
    producer: FutureProducer,
}

impl ServiceContext {
    pub fn new(config: Configuration, db: Database, active_policy: Arc<RwLock<PolicyDB>>) -> Self {
        ServiceContext {
            db,
            config: config.clone(),
            active_policy,

            #[cfg(feature = "kafka")]
            producer: crate::utils::kafka::producer::producer(&config),
        }
    }

    #[allow(unused_variables)]
    pub async fn send(&self, topic: &str, payload: Value, version: u8) -> Result<(), VaultError> {
        #[cfg(feature = "kafka")]
        crate::utils::kafka::producer::send(
            &self.producer,
            &self.config,
            topic,
            &payload.to_string(),
            version).await?;

        Ok(())
    }
}

///
/// Implemention for all the gRPC service endpoints defined in the .proto file.
///
#[tonic::async_trait]
impl PasswordService for ServiceContext {
    type ImportPasswordsStream = Pin<Box<dyn Stream<Item = Result<ImportPasswordResponse, Status>> + Send + Sync>>;
    type DeletePasswordsStream = Pin<Box<dyn Stream<Item = Result<DeleteResponse, Status>> + Send + Sync>>;

    #[instrument(skip(self, request))]
    async fn create_password_policy(&self, request: Request<CreatePolicyRequest>) -> Result<Response<CreatePolicyResponse>, Status> {
        create_policy::create_password_policy(self, request).await
    }

    #[instrument(skip(self))]
    async fn get_active_policy(&self, _request: Request<Empty>) -> Result<Response<GetActivePolicyResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn make_active(&self, _request: Request<MakeActiveRequest>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn get_policies(&self, _request: Request<Empty>) -> Result<Response<GetPoliciesResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn import_passwords(&self, _request: Request<Streaming<ImportPasswordRequest>>) -> Result<Response<Self::ImportPasswordsStream>, Status>  {
        todo!()
    }

    #[instrument(skip(self, request))]
    async fn hash_password(&self, request: Request<HashRequest>) -> Result<Response<HashResponse>, Status> {
        hash_password::hash_password(self, request).await
    }

    #[instrument(skip(self))]
    async fn validate_password(&self, request: Request<ValidateRequest>) -> Result<Response<ValidateResponse>, Status> {
        validate_password::validate_password(self, request).await
    }

    #[instrument(skip(self))]
    async fn start_reset_password(&self, _request: Request<StartResetRequest>) -> Result<Response<StartResetResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn complete_reset_password(&self, _request: Request<CompleteResetRequest>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn invalidate_password(&self, _request: Request<InvalidateRequest>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn change_password(&self, _request: Request<ChangeRequest>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn delete_password(&self, _request: Request<DeleteRequest>) -> Result<Response<DeleteResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn delete_passwords(&self, _request: Request<Streaming<DeleteRequest>>) -> Result<Response<Self::DeletePasswordsStream>, Status>  {
        todo!()
    }

    async fn ping(&self, _request:Request<Empty>) -> Result<Response<Empty>, Status> {
        println!("been pinged");
        return Ok(Response::new(Empty::default()))
    }
}
