mod create_policy;
mod hash_password;
mod validate_password;
mod set_time;
mod reset_time;

use chrono::{DateTime, Utc};
use futures::Stream;
use mongodb::Database;
use serde_json::Value;
use tracing::instrument;
use parking_lot::RwLock;
use std::{pin::Pin, sync::Arc};
use crate::utils::errors::VaultError;
use crate::grpc::{api, admin, common};
use crate::grpc::api::vault_server::Vault;
use crate::grpc::admin::admin_server::Admin;
use crate::utils::time_provider::TimeProvider;
use tonic::{Request, Response, Status, Streaming};
use crate::{model::policy::PolicyDB, utils::config::Configuration};

#[cfg(feature = "kafka")]
use rdkafka::producer::FutureProducer;

///
/// The context is available to all gRPC service endpoints and gives them access to the DB, Kafka, config, etc.
///
pub struct ServiceContext {
    db: Database,

    active_policy: Arc<RwLock<PolicyDB>>, // TODO: Ctx is in it's own Arc, do we need this one?

    time_provider: RwLock<TimeProvider>,

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
            time_provider: RwLock::new(TimeProvider::default()),

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

    pub fn now(&self) -> DateTime<Utc> {
        self.time_provider.read().now()
    }

    ///
    /// Set or clear the fixed time - if the request is succsseful returns true.
    ///
    /// It's possible that lock poisoning means this cannot be completed.
    ///
    pub fn set_now(&self, now: Option<DateTime<Utc>>) {
        self.time_provider.write().fix(now);
    }
}

///
/// Implemention for all the gRPC service endpoints defined in the .proto file.
///
#[tonic::async_trait]
impl Vault for Arc<ServiceContext> {
    type ImportPasswordsStream = Pin<Box<dyn Stream<Item = Result<api::ImportPasswordResponse, Status>> + Send + Sync>>;
    type DeletePasswordsStream = Pin<Box<dyn Stream<Item = Result<api::DeleteResponse, Status>> + Send + Sync>>;

    #[instrument(skip(self, request))]
    async fn create_password_policy(&self, request: Request<api::CreatePolicyRequest>) -> Result<Response<api::CreatePolicyResponse>, Status> {
        create_policy::create_password_policy(self, request).await
    }

    #[instrument(skip(self))]
    async fn get_active_policy(&self, _request: Request<common::Empty>) -> Result<Response<api::GetActivePolicyResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn make_active(&self, _request: Request<api::MakeActiveRequest>) -> Result<Response<common::Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn get_policies(&self, _request: Request<common::Empty>) -> Result<Response<api::GetPoliciesResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn import_passwords(&self, _request: Request<Streaming<api::ImportPasswordRequest>>) -> Result<Response<Self::ImportPasswordsStream>, Status>  {
        todo!()
    }

    #[instrument(skip(self, request))]
    async fn hash_password(&self, request: Request<api::HashRequest>) -> Result<Response<api::HashResponse>, Status> {
        hash_password::hash_password(self, request).await
    }

    #[instrument(skip(self))]
    async fn validate_password(&self, request: Request<api::ValidateRequest>) -> Result<Response<api::ValidateResponse>, Status> {
        validate_password::validate_password(self, request).await
    }

    #[instrument(skip(self))]
    async fn start_reset_password(&self, _request: Request<api::StartResetRequest>) -> Result<Response<api::StartResetResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn complete_reset_password(&self, _request: Request<api::CompleteResetRequest>) -> Result<Response<common::Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn invalidate_password(&self, _request: Request<api::InvalidateRequest>) -> Result<Response<common::Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn change_password(&self, _request: Request<api::ChangeRequest>) -> Result<Response<common::Empty>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn delete_password(&self, _request: Request<api::DeleteRequest>) -> Result<Response<api::DeleteResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn delete_passwords(&self, _request: Request<Streaming<api::DeleteRequest>>) -> Result<Response<Self::DeletePasswordsStream>, Status>  {
        todo!()
    }
}

#[tonic::async_trait]
impl Admin for Arc<ServiceContext> {
    async fn ping(&self, _request:Request<common::Empty>) -> Result<Response<common::Empty>, Status> {
        return Ok(Response::new(common::Empty::default()))
    }

    async fn set_time(&self, request: Request<admin::NewTime>) -> Result<Response<common::Empty>, Status> {
        set_time::set_time(self, request).await
    }

    async fn reset_time(&self, request: Request<common::Empty>) -> Result<Response<common::Empty>, Status> {
        reset_time::reset_time(self, request).await
    }
}