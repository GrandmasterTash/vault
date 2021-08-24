mod common;
use tonic::Code;
use crate::common::{TestConfig, start_vault};


#[tokio::test]
async fn test_a_new_password_validates_with_default_settings() {
    // Lock a mutex to guarentee sequential testing.
    let mut ctx = start_vault(TestConfig::default()).await;

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
async fn test_a_new_password_validates_with_default_settings_with_known_id() {
    // Lock a mutex to guarentee sequential testing.
    let mut ctx = start_vault(TestConfig::default()).await;
    let password_id = uuid::Uuid::new_v4().to_hyphenated().to_string();

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok("Hello123!", Some(&password_id), &mut ctx).await;
    assert_eq!(&response.password_id, &password_id);

    // Validate the password is okay.
    let response = helper::validate_password_assert_ok("Hello123!", &password_id, &mut ctx).await;
    assert_eq!(response.must_change, false);

    // Validate an incorrect password does NOT match it.
    let status = helper::validate_password_assert_err("Hello456!", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);
}


#[tokio::test]
async fn test_password_is_a_banned_phrase_with_defaults() {
    // Lock a mutex to guarentee sequential testing.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Create a new hashed password containing a banned phrase.
    let status = helper::hash_password_assert_err("!password123", None, &mut ctx).await;
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(helper::error_code(status), 2001 /* PasswordContainsBannedPhrase */);
}


#[tokio::test]
async fn test_max_failures_is_enforced_with_defaults() {
    // Lock a mutex to guarentee sequential testing.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Set the clock to a fixed point in time.
    helper::set_time("2021-08-23T09:30:00Z", &mut ctx).await;

    // Create a new hashed password.
    let response = helper::hash_password_assert_ok("W!bbl321", None, &mut ctx).await;
    let password_id = response.password_id;

    for _ in 0..=3 { /* Repeat 3 times. Why 1..3 couldn't be used is beyond me */
        // Using an incorrect password should fail 3 times before lock-out.
        let status = helper::validate_password_assert_err("Hello456!", &password_id, &mut ctx).await;
        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);
    }

    // Now that max attempts is exceeded, we should be locked out if try again.
    let status = helper::validate_password_assert_err("Hello456!", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2102 /* TooManyFailedAttempts */);

    // Wait for the default lockout period (60 seconds) to expire - we'll just travel through time an hour.
    helper::set_time("2021-08-23T10:30:00Z", &mut ctx).await;

    // Test the invalid password now gives a does not match error again.
    let status = helper::validate_password_assert_err("Hello456!", &password_id, &mut ctx).await;
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(helper::error_code(status), 2103 /* PasswordNotMatch */);

    // Test valid password is okay after a lockout.
    let response = helper::hash_password_assert_ok("W!bbl321", Some(&password_id), &mut ctx).await;
    assert_eq!(&response.password_id, &password_id);
}

// TODO: Test the policy validation rules - UNIT TESTS. But do one here.
// TODO: Test changing password checks the history limits.
// TODO: Test new policy affects password validation - need getActivePolicy before we can do this.


mod helper {
    use vault::grpc::{admin, api, common};
    use tonic::{Request, Status};
    use super::common::TestContext;
    use parking_lot::{RawMutex, lock_api::MutexGuard};

    ///
    /// Parse a numeric error code out of the body of an error Status response.
    ///
    pub fn error_code(status: Status) -> u32 {
        let raw = String::from_utf8(status.details().to_vec()).expect("Could not get an error code from the details of the status/response");
        raw.parse::<u32>().expect("The error code could not be parsed to a number")
    }

    ///
    /// Test helper to set vault to use a fixed time whenever it calls .now().
    ///
    pub async fn set_time(new_time: &str, ctx: &mut MutexGuard<'_, RawMutex, TestContext>) {
        ctx.admin().set_time(
            Request::new(
                admin::NewTime { new_time: new_time.to_string() } ))
                .await
                .unwrap();
    }

    ///
    /// Test helper to set vault to use the normal clock for .now().
    ///
    pub async fn _reset_time(ctx: &mut MutexGuard<'_, RawMutex, TestContext>) {
        ctx.admin().reset_time(Request::new(common::Empty::default()))
            .await
            .unwrap();
    }

    ///
    /// Test helper to call the hash password API when the response is expected to be success.
    ///
    pub async fn hash_password_assert_ok(plain_text_password: &str, password_id: Option<&str>, ctx: &mut MutexGuard<'_, RawMutex, TestContext>)
        -> api::HashResponse {

        ctx.client()
            .hash_password(Request::new(api::HashRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.map(|s|s.to_string())
            }))
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
    }

    ///
    /// Test helper to call the hash password API when the response is expected to be an error Status.
    ///
    pub async fn hash_password_assert_err(plain_text_password: &str, password_id: Option<&str>, ctx: &mut MutexGuard<'_, RawMutex, TestContext>)
        -> Status {

        ctx.client().hash_password(Request::new(api::HashRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.map(|s|s.to_string())
            }))
            .await
            .err()
            .unwrap() // This is the effective assert.
    }

    ///
    /// Test helper to call the validate password API when the response is expected to be success.
    ///
    pub async fn validate_password_assert_ok(plain_text_password: &str, password_id: &str, ctx: &mut MutexGuard<'_, RawMutex, TestContext>)
        -> api::ValidateResponse {

        ctx.client()
            .validate_password(Request::new(api::ValidateRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.to_string(),
            }))
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
    }

    ///
    /// Test helper to call the validate password API when the response is expected to be an error Status.
    ///
    pub async fn validate_password_assert_err(plain_text_password: &str, password_id: &str, ctx: &mut MutexGuard<'_, RawMutex, TestContext>)
        -> Status {

        ctx.client().validate_password(Request::new(api::ValidateRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.to_string(),
            }))
            .await
            .err()
            .unwrap() // This is the effective assert.
    }
}