use tonic::{Code, Request};
use vault::grpc::{HashRequest, ValidateRequest};

use crate::common::{TestConfig, start_vault};
mod common;

#[tokio::test]
async fn test_a_new_password_validates_with_default_settings() {
    // Lock a mutex to guarentee sequential testing.
    let mut ctx = start_vault(TestConfig::default()).await;

    // Create a new hashed password.
    let response = ctx.client().hash_password(Request::new(HashRequest {
            plain_text_password: "Hello123!".to_string(),
            password_id: None
        })).await.unwrap().into_inner();

    let password_id = response.password_id;
    assert_ne!(password_id.len(), 0);

    // Validate the password is okay.
    let response = ctx.client().validate_password(Request::new(ValidateRequest {
            password_id: password_id.clone(),
            plain_text_password: "Hello123!".to_string(),
        })).await.unwrap().into_inner(); // If unwrap doesn't pop, then the call is okay.

    assert_eq!(response.must_change, false);

    // Validate an incorrect password does NOT match it.
    let response = ctx.client().validate_password(Request::new(ValidateRequest {
        password_id,
        plain_text_password: "Hello456!".to_string(),
    })).await;

    let status = response.err().unwrap();
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(status.details(), "2103".as_bytes());
}

#[tokio::test]
async fn test_a_new_password_with_known_id_validates_with_default_settings() {
    // Lock a mutex to guarentee sequential testing.
    let mut ctx = start_vault(TestConfig::default()).await;
    let password_id = uuid::Uuid::new_v4().to_hyphenated().to_string();

    // Create a new hashed password.
    let response = ctx.client().hash_password(Request::new(HashRequest {
            plain_text_password: "Hello123!".to_string(),
            password_id: Some(password_id.clone())
        })).await.unwrap().into_inner();

    assert_eq!(&response.password_id, &password_id);

    // Validate the password is okay.
    let response = ctx.client().validate_password(Request::new(ValidateRequest {
            password_id: password_id.clone(),
            plain_text_password: "Hello123!".to_string(),
        })).await.unwrap().into_inner(); // If unwrap doesn't pop, then the call is okay.

    assert_eq!(response.must_change, false);

    // Validate an incorrect password does NOT match it.
    let response = ctx.client().validate_password(Request::new(ValidateRequest {
        password_id,
        plain_text_password: "Hello456!".to_string(),
    })).await;

    let status = response.err().unwrap();
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(status.details(), "2103".as_bytes());
}

// TODO: Test a password containing 'password' is banned with the default policy.

// TODO: Test a failing x times locks out. confirm with valid pwd after lock-out.
// TODO: Test valid password is okay after a lockout.
// TODO: Test the policy validation rules - UNIT TESTS. But do one here.
// TODO: Test chaning password checks the history limits.

#[tokio::test]
async fn test_something_else() {
    // Lock a mutex to guarentee sequential testing.
    let _lock = start_vault(TestConfig::default()).await;

    // Start the app.

    // Call an api.
    // tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

}
