mod create_policy;
mod hash_password;
mod validate_password;
mod get_active_policy;
mod make_active;
mod set_time;

use futures::Stream;
use tracing::instrument;
use std::{pin::Pin, sync::Arc};
use crate::grpc::{api, admin, common};
use crate::grpc::api::vault_server::Vault;
use crate::utils::context::ServiceContext;
use crate::grpc::admin::admin_server::Admin;
use tonic::{Request, Response, Status, Streaming};


///
/// Implemention for all the gRPC service endpoints defined in the vault.proto file.
///
#[tonic::async_trait]
impl Vault for Arc<ServiceContext> {
    type ImportPasswordsStream = Pin<Box<dyn Stream<Item = Result<api::ImportPasswordResponse, Status>> + Send + Sync>>;
    type DeletePasswordsStream = Pin<Box<dyn Stream<Item = Result<api::DeleteResponse, Status>> + Send + Sync>>;

    #[instrument(skip(self, request), fields(remote_addr=?request.remote_addr().unwrap()))]
    async fn create_password_policy(&self, request: Request<api::CreatePolicyRequest>) -> Result<Response<api::CreatePolicyResponse>, Status> {
        create_policy::create_password_policy(self, request).await
    }

    #[instrument(skip(self, request), fields(remote_addr=?request.remote_addr().unwrap()))]
    async fn get_active_policy(&self, request: Request<common::Empty>) -> Result<Response<api::GetActivePolicyResponse>, Status> {
        get_active_policy::get_active_policy(&self, request).await
    }

    #[instrument(skip(self, request), fields(remote_addr=?request.remote_addr().unwrap(), policy_id=?request.get_ref().policy_id))]
    async fn make_active(&self, request: Request<api::MakeActiveRequest>) -> Result<Response<common::Empty>, Status> {
        make_active::make_active(self, request).await
    }

    #[instrument(skip(self, _request), fields(remote_addr=?_request.remote_addr().unwrap()))]
    async fn get_policies(&self, _request: Request<common::Empty>) -> Result<Response<api::GetPoliciesResponse>, Status> {
        todo!()
    }

    #[instrument(skip(self, _request), fields(remote_addr=?_request.remote_addr().unwrap()))]
    async fn import_passwords(&self, _request: Request<Streaming<api::ImportPasswordRequest>>) -> Result<Response<Self::ImportPasswordsStream>, Status>  {
        todo!()
    }

    #[instrument(skip(self, request), fields(remote_addr=?request.remote_addr().unwrap(), password_id=?request.get_ref().password_id))]
    async fn hash_password(&self, request: Request<api::HashRequest>) -> Result<Response<api::HashResponse>, Status> {
        hash_password::hash_password(self, request).await
    }

    #[tracing::instrument(skip(self , request), fields(remote_addr=?request.remote_addr().unwrap(), password_id=?request.get_ref().password_id))]
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

///
/// Implemention for all the gRPC service endpoints defined in the admin.proto file.
///
#[tonic::async_trait]
impl Admin for Arc<ServiceContext> {
    async fn ping(&self, _request:Request<common::Empty>) -> Result<Response<common::Empty>, Status> {
        return Ok(Response::new(common::Empty::default()))
    }

    async fn set_time(&self, request: Request<admin::NewTime>) -> Result<Response<common::Empty>, Status> {
        set_time::set_time(self, request).await
    }

    async fn reset_time(&self, request: Request<common::Empty>) -> Result<Response<common::Empty>, Status> {
        set_time::reset_time(self, request).await
    }
}