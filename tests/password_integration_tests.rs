mod common;
use uuid::Uuid;
use tonic::Code;
use vault::grpc::api;
use chrono::{DateTime, Utc};
use crate::common::{TestConfig, helper, start_vault};


#[tokio::test]
async fn test_a_new_password_validates_with_generated_id() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok("Hello123!", None, None, &mut ctx).await;
    let password_id = response.password_id;
    assert_ne!(password_id.len(), 0);

    // Validate the password is okay.
    let response = helper::validate_password_assert_ok("Hello123!", &password_id, &mut ctx).await;
    assert_eq!(response, true);

    // Validate an incorrect password does NOT match it.
    let status = helper::validate_password_assert_err("Hello456!", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);
}


#[tokio::test]
async fn test_a_new_password_validates_with_provided_id() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    let password_id = Uuid::new_v4().to_hyphenated().to_string();

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok("Hello123!", Some(&password_id), None, &mut ctx).await;
    assert_eq!(&response.password_id, &password_id);

    // Validate the password is okay.
    let response = helper::validate_password_assert_ok("Hello123!", &password_id, &mut ctx).await;
    assert_eq!(response, true);

    // Validate an incorrect password does NOT match it.
    let status = helper::validate_password_assert_err("Hello456!", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);
}


#[tokio::test]
async fn test_a_password_expires_after_a_period_of_time() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    let password_id = Uuid::new_v4().to_hyphenated().to_string();

    // Set the clock to a fixed point in time.
    helper::set_time("2021-08-23T09:30:00Z", &mut ctx).await;

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok("Hello123!", Some(&password_id), None, &mut ctx).await;
    assert_eq!(&response.password_id, &password_id);

    // Time-travel to > 30 days later.
    helper::set_time("2021-09-28T09:30:00Z", &mut ctx).await;

    // Validate the password is okay but expired
    let status = helper::validate_password_assert_err("Hello123!", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::DeadlineExceeded);
    assert_eq!(helper::error_code(status), 2104 /* PasswordExpired */);
}


#[tokio::test]
async fn test_a_new_password_containing_banned_phrase_is_rejected() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    // Create a new hashed password containing a banned phrase.
    let status = helper::hash_password_assert_err("!password123", None, &mut ctx).await;
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(helper::error_code(status), 2001 /* PasswordContainsBannedPhrase */);
}


#[tokio::test]
async fn test_max_failures_is_enforced() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    const GOOD_PWD: &str = "W!bbl321";
    const BAD_PWD:  &str = "Hello456!";

    // Set the clock to a fixed point in time.
    helper::set_time("2021-08-23T09:30:00Z", &mut ctx).await;

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok(GOOD_PWD, None, None, &mut ctx).await;
    let password_id = response.password_id;

    for _ in 0..=3 { /* Repeat 3 times. Why 1..3 couldn't be used is beyond me */
        // Using an incorrect password should fail 3 times before lock-out.
        let status = helper::validate_password_assert_err(BAD_PWD, &password_id, &mut ctx).await;
        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);
    }

    // Now that max attempts is exceeded, we should be locked out if we try again.
    let status = helper::validate_password_assert_err(GOOD_PWD, &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2102 /* TooManyFailedAttempts */);

    // Wait for the default lockout period (60 seconds) to expire - we'll just travel through time an hour.
    helper::set_time("2021-08-23T10:30:00Z", &mut ctx).await;

    // Test the invalid password now gives a 'does not match' error again.
    let status = helper::validate_password_assert_err(BAD_PWD, &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);

    // Test the valid password is okay after the lockout.
    let response = helper::validate_password_assert_ok(GOOD_PWD, &password_id, &mut ctx).await;
    assert_eq!(response, true);
}


#[tokio::test]
async fn test_new_policy_can_be_retreived() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Set the clock to a fixed point in time. So we can tested the createdOn.
    let now = "2021-08-23T09:30:00Z";
    helper::set_time(now, &mut ctx).await;

    let policy = api::NewPolicy {
        max_history_length: 1,
        max_age_days: 2,
        min_length: 3,
        max_length: 24,
        max_character_repeat: 5,
        min_letters: 6,
        max_letters: 7,
        min_numbers: 8,
        max_numbers: 9,
        min_symbols: 10,
        max_symbols: 11,
        max_failures: 12,
        lockout_seconds: 13,
        mixed_case_required: true,
        reset_timeout_seconds: 14,
        prohibited_phrases: vec!(String::from("1234")),
        algorithm: Some(api::new_policy::Algorithm::ArgonPolicy(api::ArgonPolicy {
            parallelism: 15,
            tag_length: 16,
            memory_size_kb: 17,
            iterations: 18,
            version: 19,
            hash_type: 2,
        })),
    };

    let response = helper::create_policy_assert_ok(policy.clone(), "DEFAULT", true, &mut ctx).await;
    let policy_id = response.policy_id;
    assert_ne!(policy_id.len(), 0);

    // Active policy is updated with eventual consistency, we'll wait for up to 10 seconds
    // for it to update.
    let actual_policy = helper::wait_until_active(&policy_id, "DEFAULT", ctx.client()).await;

    // Are all the fields on the active policy what we specified and expected?
    assert_eq!(actual_policy.policy_id, policy_id);
    assert_eq!(actual_policy.created_on, DateTime::parse_from_rfc3339(now).expect("test date wont parse").timestamp_millis() as u64);
    assert_eq!(actual_policy.max_history_length, 1);
    assert_eq!(actual_policy.max_age_days, 2);
    assert_eq!(actual_policy.min_length, 3);
    assert_eq!(actual_policy.max_length, 24);
    assert_eq!(actual_policy.max_character_repeat, 5);
    assert_eq!(actual_policy.min_letters, 6);
    assert_eq!(actual_policy.max_letters, 7);
    assert_eq!(actual_policy.min_numbers, 8);
    assert_eq!(actual_policy.max_numbers, 9);
    assert_eq!(actual_policy.min_symbols, 10);
    assert_eq!(actual_policy.max_symbols, 11);
    assert_eq!(actual_policy.max_failures, 12);
    assert_eq!(actual_policy.lockout_seconds, 13);
    assert_eq!(actual_policy.mixed_case_required, true);
    assert_eq!(actual_policy.reset_timeout_seconds, 14);
    assert_eq!(actual_policy.prohibited_phrases, vec!(String::from("1234")));

    let actual_algorithm: api::policy::Algorithm = actual_policy.algorithm.unwrap();
    match actual_algorithm {
        api::policy::Algorithm::ArgonPolicy(actual_algorithm) => {
            assert_eq!(actual_algorithm.parallelism, 15);
            assert_eq!(actual_algorithm.tag_length, 16);
            assert_eq!(actual_algorithm.memory_size_kb, 17);
            assert_eq!(actual_algorithm.iterations, 18);
            assert_eq!(actual_algorithm.version, 19);
            assert_eq!(actual_algorithm.hash_type, 2);
        },
        wrong @ _ => panic!("Wrong policy type returned {:?}", wrong)
    };
}

#[tokio::test]
async fn test_new_policy_enforced_with_new_passwords() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Create a 4-digit PIN policy.
    let policy = api::NewPolicy {
        max_history_length: 0,
        max_age_days: 99999,
        min_length: 4,
        max_length: 4,
        max_character_repeat: 4,
        min_letters: 0,
        max_letters: 0,
        min_numbers: 4,
        max_numbers: 4,
        min_symbols: 0,
        max_symbols: 0,
        max_failures: 4,
        lockout_seconds: 100,
        mixed_case_required: false,
        reset_timeout_seconds: 30,
        prohibited_phrases: vec!("1234".to_string(), "0000".to_string()),
        algorithm: Some(api::new_policy::Algorithm::ArgonPolicy(api::ArgonPolicy {
            parallelism: 1,
            tag_length: 16,
            memory_size_kb: 8,
            iterations: 1,
            version: 19,
            hash_type: 2,
        })),
    };

    let response = helper::create_policy_assert_ok(policy.clone(), "PIN", true, &mut ctx).await;
    let policy_id = response.policy_id;
    let _ = helper::wait_until_active(&policy_id, "PIN", ctx.client()).await;

    // Create a new hashed pin.
    let response = helper::hash_password_assert_ok("1122", None, Some("PIN"), &mut ctx).await;
    let password_id = response.password_id;
    assert_ne!(password_id.len(), 0);

    // Validate the password is okay.
    let response = helper::validate_password_assert_ok("1122", &password_id, &mut ctx).await;
    assert_eq!(response, true);

    // Validate an incorrect password does NOT match it.
    let status = helper::validate_password_assert_err("1234", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);
}

#[tokio::test]
async fn test_two_phase_password_reset() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    // Hash a new password.
    let response = helper::hash_password_assert_ok("G0nn@r3s3t", None, None, &mut ctx).await;
    let password_id = response.password_id;
    assert_ne!(password_id.len(), 0);

    // Get a reset code.
    let request = api::StartResetRequest { password_id: password_id.clone() };
    let response = ctx.client().start_reset_password(request).await.unwrap().into_inner();
    let reset_code = response.reset_code;
    assert_ne!(reset_code.len(), 0);

    // Complete the reset.
    let request = api::CompleteResetRequest { password_id: password_id.clone(), reset_code, plain_text_password: "R3s3tP@sword".to_string() };
    let _response = ctx.client().complete_reset_password(request).await.unwrap().into_inner();

    // Ensure the new password is valid.
    let response = helper::validate_password_assert_ok("R3s3tP@sword", &password_id, &mut ctx).await;
    assert_eq!(response, true);

    // Ensure the old password is not valid.
    let status = helper::validate_password_assert_err("G0nn@r3s3t", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);
}

#[tokio::test]
async fn test_delete_password_by_id() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    // Hash two new passwords.
    let response = helper::hash_password_assert_ok("D3l3teM@", None, None, &mut ctx).await;
    let password_1_id = response.password_id;
    assert_ne!(password_1_id.len(), 0);

    let response = helper::hash_password_assert_ok("D0ntD3l3teM@", None, None, &mut ctx).await;
    let password_2_id = response.password_id;
    assert_ne!(password_2_id.len(), 0);

    // Delete password 1 by id.
    let request = api::DeleteRequest { delete_by: Some(api::delete_request::DeleteBy::PasswordId(password_1_id.clone())) };
    let response = ctx.client().delete_password(request).await.unwrap().into_inner();
    assert_eq!(response.deleted_count, 1);

    // Ensure it's deleted.
    let status = helper::validate_password_assert_err("D3l3teM@", &password_1_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2101 /* PasswordNotFound */);

    // Ensure the other password is not deleted.
    let response = helper::validate_password_assert_ok("D0ntD3l3teM@", &password_2_id, &mut ctx).await;
    assert_eq!(response, true);
}

#[tokio::test]
async fn test_delete_passwords_by_type() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Generate a unique password_type.
    let password_type = format!("type_{}", Utc::now().timestamp_millis());

    let response = helper::create_policy_assert_ok(helper::sensible_policy(), &password_type, true, &mut ctx).await;
    let policy_id = response.policy_id;
    let _ = helper::wait_until_active(&policy_id, &password_type, ctx.client()).await;

    // Hash two new passwords.
    let response = helper::hash_password_assert_ok("D3l3teM@", None, Some(&password_type), &mut ctx).await;
    let password_1_id = response.password_id;
    assert_ne!(password_1_id.len(), 0);

    let response = helper::hash_password_assert_ok("D0ntD3l3teM@", None, Some(&password_type), &mut ctx).await;
    let password_2_id = response.password_id;
    assert_ne!(password_2_id.len(), 0);

    // Delete all passwords by password type.
    let request = api::DeleteRequest { delete_by: Some(api::delete_request::DeleteBy::PasswordType(password_type.clone())) };
    let response = ctx.client().delete_password(request).await.unwrap().into_inner();
    assert_eq!(response.deleted_count, 2);

    // Ensure one of them is deleted.
    let status = helper::validate_password_assert_err("D3l3teM@", &password_1_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2101 /* PasswordNotFound */);
}

#[tokio::test]
async fn test_delete_password_type() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Generate a unique password_type.
    let password_type = format!("type_{}", Utc::now().timestamp_millis());

    let response = helper::create_policy_assert_ok(helper::sensible_policy(), &password_type, true, &mut ctx).await;
    let policy_id = response.policy_id;
    let _ = helper::wait_until_active(&policy_id, &password_type, ctx.client()).await;

    // Hash two new passwords.
    let response = helper::hash_password_assert_ok("D3l3teM@", None, Some(&password_type), &mut ctx).await;
    let password_1_id = response.password_id;
    assert_ne!(password_1_id.len(), 0);

    let response = helper::hash_password_assert_ok("D0ntD3l3teM@", None, Some(&password_type), &mut ctx).await;
    let password_2_id = response.password_id;
    assert_ne!(password_2_id.len(), 0);

    // Delete password type (configuration and passwords).
    let request = api::DeletePasswordTypeRequest { password_type };
    let response = ctx.client().delete_password_type(request).await.unwrap().into_inner();
    assert_eq!(response.deleted_count, 2); // Number of passwords with the type.

    // Ensure one of them is deleted.
    let status = helper::validate_password_assert_err("D3l3teM@", &password_1_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2101 /* PasswordNotFound */);
}

#[tokio::test]
async fn test_delete_default_password_type_is_prohibited() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    let request = api::DeletePasswordTypeRequest { password_type: "DEFAULT".to_string() };
    let status = ctx.client().delete_password_type(request).await.err().unwrap();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(helper::error_code(status), 2401 /* CannotRemoveDefault */);

}


// TODO: Test get policies.

// TODO: Test get active policy.

// TODO: Test get password types.

// TODO: Test the validation checks in create policy api handler.


