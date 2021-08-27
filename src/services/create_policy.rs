use std::ops::Range;
use serde_json::json;
use super::ServiceContext;
use crate::services::make_active;
use tonic::{Request, Response, Status};
use crate::model::policy::PolicyDB;
use crate::utils::{errors::ErrorCode, mongo};
use crate::{utils::errors::VaultError, grpc::api};

const ARGON_PARALELLISM: Range<u32> = 1..2^24;
const ARGON_TAG_LENGTH:  Range<u32> = 4..2^32;
// const V1: u8 = 1;

///
/// Create and potentially activates a new password policy. The policy is used to enforce password
/// formats going forward. Existing passwords are only invalidated when next used.
///
pub async fn create_password_policy(ctx: &ServiceContext, request: Request<api::CreatePolicyRequest>)
    -> Result<Response<api::CreatePolicyResponse>, Status> {

    // Validate the request.
    let (api_policy, activate) = validate_request(request.into_inner())?;

    // Generated field values.
    let policy_id = mongo::generate_id();
    let now = ctx.now();

    // Create the policy in the db.
    let mut policy: PolicyDB = api_policy.into();
    policy.policy_id = policy_id.clone();
    policy.created_on = bson::DateTime::from_chrono(now);

    ctx.db().collection::<PolicyDB>("Policies").insert_one(policy.clone(), None)
        .await
        .map_err(|e| VaultError::from(e))?;

    ctx.send("password.policy.created", json!(policy), 1).await?;

    if activate {
        make_active::make_active_by_id(&policy_id, ctx).await?;
    }

    Ok(Response::new(api::CreatePolicyResponse { policy_id }))
}

///
/// Validate the request and return the innards if it's okay.
///
fn validate_request(request: api::CreatePolicyRequest) -> Result<(api::Policy, bool), VaultError> {
    // TODO: Reject if a policy_id is being provided.

    let policy = match request.policy {
        Some(policy) => policy,
        None => return Err(ErrorCode::PolicyMandatory.with_msg("Please provide a policy"))
    };

    match &policy.algorthm {
        Some(algorthm) => match algorthm {
            api::policy::Algorthm::ArgonPolicy(argon) => validate_argon(argon)?,
            api::policy::Algorthm::BcyrptPolicy(_bcrypt) => {}, // TODO: Validate these.
            api::policy::Algorthm::Pbkfd2Policy(_pbdkfd2) => {},
        },
        None => return Err(ErrorCode::AlgorthimMandatory.with_msg("Please provide an algorthm")),
    };

    Ok((policy, request.activate))
}

fn validate_argon(argon: &api::ArgonPolicy) -> Result<(), VaultError> {
    if !ARGON_PARALELLISM.contains(&argon.parallelism) {
        return Err(ErrorCode::InvalidArgonParalellism.with_msg(&format!("Argon parallelism must be in the range {:?}", ARGON_PARALELLISM)))
    }

    if !ARGON_TAG_LENGTH.contains(&argon.tag_length) {
        return Err(ErrorCode::InvalidArgonTaglength.with_msg(&format!("Argon tag length must be in the range {:?}", ARGON_TAG_LENGTH)))
    }

    // TODO: More but once we have an implementation.

    Ok(())
}
