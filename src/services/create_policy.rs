use crate::{db, model::config::prelude::DEFAULT};
use std::ops::Range;
use serde_json::json;
use super::ServiceContext;
use crate::model::policy::Policy;
use crate::services::make_active;
use crate::utils::errors::ErrorCode;
use tonic::{Request, Response, Status};
use crate::{utils::errors::VaultError, grpc::api};

const ARGON_PARALELLISM: Range<u32> = 1..2^24;
const ARGON_TAG_LENGTH:  Range<u32> = 4..2^32;
const BCRYPT_COST:       Range<u32> = 4..32;

///
/// Create and potentially activates a new password policy. The policy is used to enforce password
/// formats going forward. Existing passwords are only invalidated when next used.
///
pub async fn create_password_policy(ctx: &ServiceContext, request: Request<api::CreatePolicyRequest>)
    -> Result<Response<api::CreatePolicyResponse>, Status> {

    // Validate the request.
    let request = request.into_inner();
    validate_request(&request.policy)?;

    // Generated field values.
    let policy_id = db::mongo::generate_id();
    let now = ctx.now();

    // Create the policy in the db.
    let mut policy: Policy = request.policy.unwrap().into();
    policy.policy_id = policy_id.clone();
    policy.created_on = bson::DateTime::from_chrono(now);

    // TODO: Move to db::policy
    ctx.db().collection::<Policy>("Policies").insert_one(policy.clone(), None)
        .await
        .map_err(|e| VaultError::from(e))?;

    ctx.send("password.policy.created", json!(policy), 1).await?;

    if request.activate {
        make_active::make_active_by_id(
            &policy_id,
            request.password_type.as_deref().unwrap_or(DEFAULT),
            ctx).await?;
    }

    Ok(Response::new(api::CreatePolicyResponse { policy_id }))
}

///
/// Validate the request and return the innards if it's okay.
///
fn validate_request(policy: &Option<api::NewPolicy>) -> Result<(), VaultError> {
    // TODO: Reject if a policy_id is being provided.

    let policy = match policy {
        Some(policy) => policy,
        None => return Err(ErrorCode::PolicyMandatory.with_msg("Please provide a policy"))
    };

    // Validate the main fields on the policy make sense.
    // TODO: xx min < max, etc. min > -1, at chars+symbols+numbers > 0

    match &policy.algorithm {
        Some(algorithm) => match algorithm {
            api::new_policy::Algorithm::ArgonPolicy(argon) => validate_argon(argon, &policy)?,
            api::new_policy::Algorithm::BcryptPolicy(bcrypt) => validate_bcrypt(bcrypt, &policy)?,
            api::new_policy::Algorithm::Pbkdf2Policy(pbkdf2) => validate_pbkdf2(pbkdf2, &policy)?,
        },
        None => return Err(ErrorCode::AlgorthimMandatory.with_msg("Please provide an algorithm")),
    };

    Ok(())
}

fn validate_argon(argon: &api::ArgonPolicy, policy: &api::NewPolicy) -> Result<(), VaultError> {
    if !ARGON_PARALELLISM.contains(&argon.parallelism) {
        return Err(ErrorCode::InvalidArgonParalellism.with_msg(&format!("Argon parallelism must be in the range {:?}", ARGON_PARALELLISM)))
    }

    if !ARGON_TAG_LENGTH.contains(&argon.tag_length) {
        return Err(ErrorCode::InvalidArgonTaglength.with_msg(&format!("Argon tag length must be in the range {:?}", ARGON_TAG_LENGTH)))
    }

    // TODO: More but once we have an implementation.

    Ok(())
}

fn validate_bcrypt(bcrypt: &api::BCryptPolicy, policy: &api::NewPolicy) -> Result<(), VaultError> {

    if !BCRYPT_COST.contains(&bcrypt.cost) {
        return Err(ErrorCode::InvalidBcryptCost.with_msg(&format!("Bcrypt cost must be in the range {:?}", BCRYPT_COST)))
    }

    Ok(())
}

fn validate_pbkdf2(pbkdf2: &api::Pbkdf2Policy, policy: &api::NewPolicy) -> Result<(), VaultError> {

    // TODO: Cost should be more than zero.

    // TODO: This should match the policy max password len.
    // policy.dk_len

    Ok(())
}
