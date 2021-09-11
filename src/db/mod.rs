pub mod mongo;
pub mod policy;
pub mod password;

// TODO: Prelude with all collection names.

// This ensures only one persisted document exists.
pub mod prelude {
    // Default ID's / password_types.
    pub const DEFAULT: &str = "DEFAULT";

    // Collection names.
    pub const POLICIES:  &str = "Policies";
    pub const CONFIG:    &str = "Config";
    pub const PASSWORDS: &str = "Passwords";

    // Field names.
    pub const ACTIVE_POLICY_ID: &str = "active_policy_id";
    pub const ACTIVATED_ON:     &str = "activated_on";
    pub const CHANGED_ON:       &str = "changed_on";
    pub const FAILURE_COUNT:    &str = "failure_count";
    pub const FIRST_FAILURE:    &str = "first_failure";
    pub const HISTORY:          &str = "history";
    pub const LAST_SUCCESS:     &str = "last_success";
    pub const PHC:              &str = "phc";
    pub const POLICY_ID:        &str = "policy_id";
    pub const PASSWORD_ID:      &str = "password_id";
    pub const PASSWORD_TYPE:    &str = "password_type";
    pub const RESET_CODE:       &str = "reset_code";
    pub const RESET_STARTED_AT: &str = "reset_started_at";
}