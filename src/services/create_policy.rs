use crate::utils;
use std::ops::RangeInclusive;
use serde_json::json;
use super::ServiceContext;
use crate::{db, db::prelude::*};
use crate::model::policy::Policy;
use crate::services::make_active;
use crate::utils::kafka::prelude::*;
use crate::utils::errors::ErrorCode;
use tonic::{Request, Response, Status};
use crate::{utils::errors::VaultError, grpc::api};

const ARGON_PARALELLISM: RangeInclusive<u32> = 1..=16777216;   // 2^24
const ARGON_TAG_LENGTH:  RangeInclusive<u32> = 4..=4294967295; // 2^32;
const ARGON_MEMORY:      RangeInclusive<u32> = 8..=4294967295; // 2^32;
const ARGON_VERSIONS:    [u32; 2] = [16, 19];
const ARGON_MIN_COST:    u32 = 1;
const BCRYPT_COST:       RangeInclusive<u32> = 4..=31;
const PBKDF2_MIN_COST:   u32 = 1;
const PBKDF2_MIN_OUTPUT: u32 = 10;

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
    let policy_id = utils::generate_id();
    let now = ctx.now();

    // Create the policy in the db.
    let mut policy: Policy = request.policy.unwrap().into();
    policy.policy_id = policy_id.clone();
    policy.created_on = bson::DateTime::from_chrono(now);

    db::policy::insert(policy.clone(), ctx.db()).await?;

    ctx.send(TOPIC_POLICY_CREATED, json!(policy)).await?;

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

    let policy = match policy {
        Some(policy) => policy,
        None => return Err(ErrorCode::PolicyMandatory.with_msg("Please provide a policy"))
    };

    // Validate the main fields on the policy make sense.
    if policy.max_character_repeat < 1 {
        return Err(ErrorCode::InvalidPolicy.with_msg("The maximum character repeat value must be greater than zero"))
    }

    if policy.min_length < 1 {
        return Err(ErrorCode::InvalidPolicy.with_msg("The minimum password length must be greater than zero"))
    }

    if policy.min_length > policy.max_length {
        return Err(ErrorCode::InvalidPolicy.with_msg("The minimum password length must be less than the maximum password length"))
    }

    if policy.min_letters > policy.max_letters {
        return Err(ErrorCode::InvalidPolicy.with_msg("The minimum number of letters must be less than the maximum number of letters"))
    }

    if policy.min_numbers > policy.max_numbers {
        return Err(ErrorCode::InvalidPolicy.with_msg("The minimum number of numerics must be less than the maximum number of numerics"))
    }

    if policy.min_symbols > policy.max_symbols {
        return Err(ErrorCode::InvalidPolicy.with_msg("The minimum number of symbols must be less than the maximum number of symbols"))
    }

    let total_min = policy.min_letters + policy.min_numbers + policy.min_symbols;

    if total_min < policy.min_length {
        return Err(ErrorCode::InvalidPolicy.with_msg("The minimum number of letters, numbers and symbols combined, must be equal to or more than the minimum password length"))
    }

    if total_min > policy.max_length {
        return Err(ErrorCode::InvalidPolicy.with_msg("The minimum number of letters, numbers and symbols combined, must be less than or equal to the maximum password length"))
    }

    if policy.mixed_case_required && policy.min_letters < 2 {
        return Err(ErrorCode::InvalidPolicy.with_msg("If mixed case is enabled, the minimum number of letters must be two or more"))
    }

    match &policy.algorithm {
        Some(algorithm) => match algorithm {
            api::new_policy::Algorithm::ArgonPolicy(argon)   => validate_argon(argon)?,
            api::new_policy::Algorithm::BcryptPolicy(bcrypt) => validate_bcrypt(bcrypt)?,
            api::new_policy::Algorithm::Pbkdf2Policy(pbkdf2) => validate_pbkdf2(pbkdf2)?,
        },
        None => return Err(ErrorCode::AlgorthimMandatory.with_msg("Please provide an algorithm to hash passwords with")),
    };

    Ok(())
}

fn validate_argon(argon: &api::ArgonPolicy) -> Result<(), VaultError> {

    if !ARGON_PARALELLISM.contains(&argon.parallelism) {
        return Err(ErrorCode::InvalidArgonParalellism.with_msg(&format!("Argon parallelism must be in the range {:?}", ARGON_PARALELLISM)))
    }

    if !ARGON_TAG_LENGTH.contains(&argon.tag_length) {
        return Err(ErrorCode::InvalidArgonTaglength.with_msg(&format!("Argon tag length must be in the range {:?}", ARGON_TAG_LENGTH)))
    }

    if !ARGON_VERSIONS.contains(&argon.version) {
        return Err(ErrorCode::InvalidArgonVersion.with_msg(&format!("Argon version must be one of {:?}", ARGON_VERSIONS)))
    }

    if !ARGON_MEMORY.contains(&argon.memory_size_kb) {
        return Err(ErrorCode::InvalidArgonMemorySize.with_msg(&format!("Argon memory size must be in the range {:?}", ARGON_MEMORY)))
    }

    if argon.iterations < ARGON_MIN_COST {
        return Err(ErrorCode::InvalidArgonCost.with_msg("The cost must be greater than zero"))
    }

    Ok(())
}

fn validate_bcrypt(bcrypt: &api::BCryptPolicy) -> Result<(), VaultError> {

    if !BCRYPT_COST.contains(&bcrypt.cost) {
        return Err(ErrorCode::InvalidBcryptCost.with_msg(&format!("Bcrypt cost must be in the range {:?}", BCRYPT_COST)))
    }

    Ok(())
}

fn validate_pbkdf2(pbkdf2: &api::Pbkdf2Policy) -> Result<(), VaultError> {

    if pbkdf2.cost < PBKDF2_MIN_COST {
        return Err(ErrorCode::InvalidPbkdf2Cost.with_msg("The cost must be greater than zero"))
    }

    if pbkdf2.output_len < PBKDF2_MIN_OUTPUT {
        return Err(ErrorCode::InvalidPbkdf2OutputLen.with_msg("The output length (in bytes) must be 10 or more"))
    }

    Ok(())
}
