mod set_time;
mod start_reset;
mod make_active;
mod get_policies;
mod create_policy;
mod hash_password;
mod complete_reset;
mod delete_password;
mod import_passwords;
mod validate_password;
mod get_active_policy;
mod get_password_types;
mod delete_password_type;

use std::sync::Arc;
use tracing::instrument;
use crate::grpc::{api, internal, common};
use crate::grpc::api::vault_server::Vault;
use crate::utils::context::ServiceContext;
use tokio_stream::wrappers::ReceiverStream;
use crate::grpc::internal::internal_server::Internal;
use tonic::{Code, Request, Response, Status, Streaming};

///
/// Implemention for all the gRPC service endpoints defined in the vault.proto file.
///
#[tonic::async_trait]
impl Vault for Arc<ServiceContext> {
    type ImportPasswordsStream = ReceiverStream<Result<api::ImportPasswordResponse, Status>>;
    type DeletePasswordsStream = ReceiverStream<Result<api::DeleteResponse, Status>>;

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn create_password_policy(&self, request: Request<api::CreatePolicyRequest>) -> Result<Response<api::CreatePolicyResponse>, Status> {
        trace_status(create_policy::create_password_policy(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn get_active_policy(&self, request: Request<api::GetActivePolicyRequest>) -> Result<Response<api::GetActivePolicyResponse>, Status> {
        trace_status(get_active_policy::get_active_policy(&self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn make_active(&self, request: Request<api::MakeActiveRequest>) -> Result<Response<common::Empty>, Status> {
        trace_status(make_active::make_active(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn get_policies(&self, request: Request<common::Empty>) -> Result<Response<api::GetPoliciesResponse>, Status> {
        trace_status(get_policies::get_policies(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn import_passwords(&self, request: Request<Streaming<api::ImportPasswordRequest>>) -> Result<Response<Self::ImportPasswordsStream>, Status>  {
        trace_status(import_passwords::import_passwords(self.clone(), request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn hash_password(&self, request: Request<api::HashRequest>) -> Result<Response<api::HashResponse>, Status> {
        trace_status(hash_password::hash_password(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn validate_password(&self, request: Request<api::ValidateRequest>) -> Result<Response<common::Empty>, Status> {
        trace_status(validate_password::validate_password(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn start_reset_password(&self, request: Request<api::StartResetRequest>) -> Result<Response<api::StartResetResponse>, Status> {
        trace_status(start_reset::start_reset_password(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn complete_reset_password(&self, request: Request<api::CompleteResetRequest>) -> Result<Response<common::Empty>, Status> {
        trace_status(complete_reset::complete_reset_password(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn delete_password(&self, request: Request<api::DeleteRequest>) -> Result<Response<api::DeleteResponse>, Status> {
        trace_status(delete_password::delete_password(self.clone(), request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn delete_passwords(&self, request: Request<Streaming<api::DeleteRequest>>) -> Result<Response<Self::DeletePasswordsStream>, Status>  {
        trace_status(delete_password::delete_passwords(self.clone(), request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn get_password_types(&self, request: Request<common::Empty>) -> Result<Response<api::GetPasswordTypesResponse>, Status> {
        trace_status(get_password_types::get_password_types(self, request).await)
    }

    #[instrument(skip(self, request), fields(response.status, remote_addr=?request.remote_addr().unwrap()))]
    async fn delete_password_type(&self, request: Request<api::DeletePasswordTypeRequest>) -> Result<Response<api::DeleteResponse>, Status> {
        trace_status(delete_password_type::delete_password_type(self, request).await)
    }
}

///
/// Implemention for all the gRPC service endpoints defined in the admin.proto file.
///
#[tonic::async_trait]
impl Internal for Arc<ServiceContext> {
    async fn set_time(&self, request: Request<internal::NewTime>) -> Result<Response<common::Empty>, Status> {
        set_time::set_time(self, request).await
    }

    async fn reset_time(&self, request: Request<common::Empty>) -> Result<Response<common::Empty>, Status> {
        set_time::reset_time(self, request).await
    }
}


///
/// Trace status of each API call in response.
///
fn trace_status<T>(result: Result<Response<T>, Status>) -> Result<Response<T>, Status> {
    let status = match &result {
        Ok(_)       => Code::Ok,
        Err(status) => status.code(),
    };
    let str_status = format!("{:?}", status);
    tracing::Span::current().record("response.status", &str_status.as_str());
    result
}