mod common;
use chrono::DateTime;
use tonic::Code;
use uuid::Uuid;
use vault::grpc::api;
use crate::common::{TestConfig, helper, start_vault};


#[tokio::test]
async fn test_a_new_password_validates_with_generated_id() {
    // Start the server if needed, and ensure this test has exclusive access.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok("Hello123!", None, &mut ctx).await;
    let password_id = response.password_id;
    assert_ne!(password_id.len(), 0);

    // Validate the password is okay.
    let response = helper::validate_password_assert_ok("Hello123!", &password_id, &mut ctx).await;
    assert_eq!(response.must_change, false);

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
    let response = helper::hash_password_assert_ok("Hello123!", Some(&password_id), &mut ctx).await;
    assert_eq!(&response.password_id, &password_id);

    // Validate the password is okay.
    let response = helper::validate_password_assert_ok("Hello123!", &password_id, &mut ctx).await;
    assert_eq!(response.must_change, false); // This is a new password and wont have expired yet.

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
    let response = helper::hash_password_assert_ok("Hello123!", Some(&password_id), &mut ctx).await;
    assert_eq!(&response.password_id, &password_id);

    // Time-travel to > 30 days later.
    helper::set_time("2021-09-28T09:30:00Z", &mut ctx).await;

    // Validate the password is okay.
    let response = helper::validate_password_assert_ok("Hello123!", &password_id, &mut ctx).await;
    assert_eq!(response.must_change, true); // This password should have expired now.
}


#[tokio::test]
async fn test_a_new_password_containg_banned_phrase_is_rejected() {
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

    // Have issue where tests recieve can receive messages from previous incomplete test runs.
    // This causes them to try to load data not present.
    // Do we need unique topic names for the tests? i.e. policy.activated.test.guid?
    // KAN we use an admin client to delete the topic before the server starts?
    // tokio::time::sleep(std::time::Duration::from_millis(5000)).await;

    // Apply the default policy - other tests may have changed it.
    helper::make_active_and_wait("DEFAULT", &mut ctx).await;

    const GOOD_PWD: &str = "W!bbl321";
    const BAD_PWD:  &str = "Hello456!";

    // Set the clock to a fixed point in time.
    helper::set_time("2021-08-23T09:30:00Z", &mut ctx).await;

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok(GOOD_PWD, None, &mut ctx).await;
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
    let response = helper::hash_password_assert_ok(GOOD_PWD, Some(&password_id), &mut ctx).await;
    assert_eq!(&response.password_id, &password_id);
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
        max_length: 4,
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
    let actual_policy = helper::wait_until_active(&policy_id, ctx.client()).await;

    // Are all the fields on the active policy what we specified and expected?
    assert_eq!(actual_policy.policy_id, policy_id);
    assert_eq!(actual_policy.created_on, DateTime::parse_from_rfc3339(now).expect("test date wont parse").timestamp_millis() as u64);
    assert_eq!(actual_policy.max_history_length, 1);
    assert_eq!(actual_policy.max_age_days, 2);
    assert_eq!(actual_policy.min_length, 3);
    assert_eq!(actual_policy.max_length, 4);
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

// #[tokio::test]
// async fn test_new_policy_enforced_with_new_passwords() {
//     // Start the server if needed, and ensure this test has exclusive access.
//     // let mut ctx = start_vault(TestConfig::default()).await;

// }

// TODO: Test the policy validation rules - UNIT TESTS. But do one here.
// TODO: Test changing password checks the history limits.


