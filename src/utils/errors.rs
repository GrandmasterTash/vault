use bcrypt::BcryptError;
use mongodb::bson;
use tokio::task::JoinError;
use tonic::{Code, Status};
use bson::document::ValueAccessError;

#[cfg(feature = "kafka")]
use rdkafka::{error::KafkaError, message::OwnedMessage};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrorCode {
    TonicStartError                 = 0400,
    HashThreadingIssue              = 0401,
    UnableToReadCredentials         = 0500,
    ConfigDocumentNotFound          = 0501,
    ActivePolicyNotFound            = 0502,
    MongoDBError                    = 0503,
    InvalidBSON                     = 0504,
    InvalidJSON                     = 0505,
    KafkaSendError                  = 0506,
    BSONFieldNotFound               = 0507,
    InvalidAlgorthimConfig          = 0508,
    HashingError                    = 0509,
    InvalidPHCFormat                = 0510,
    UnknownAlgorithmVariant         = 0511,
    PolicyMandatory                 = 1000,
    PolicyNotFound                  = 1001,
    AlgorthimMandatory              = 1002,
    InvalidPolicy                   = 1003,
    InvalidArgonParalellism         = 1100,
    InvalidArgonTaglength           = 1101,
    InvalidArgonVersion             = 1102,
    InvalidArgonMemorySize          = 1103,
    InvalidArgonCost                = 1104,
    InvalidBcryptCost               = 1200,
    InvalidPbkdf2Cost               = 1300,
    InvalidPbkdf2OutputLen          = 1301,
    PasswordContainsBannedPhrase    = 2001,
    PasswordTooShort                = 2002,
    PasswordTooLong                 = 2003,
    CharacterRepeatedTooManyTimes   = 2004,
    NotEnoughLetters                = 2005,
    TooManyLetters                  = 2006,
    NotEnoughNumbers                = 2007,
    TooManyNumbers                  = 2008,
    NotEnoughSymbols                = 2009,
    TooManySymbols                  = 2010,
    NotMixedCase                    = 2011,
    PasswordUsedBefore              = 2012,
    PasswordNotFound                = 2101,
    TooManyFailedAttempts           = 2102,
    PasswordNotMatch                = 2103,
    PasswordExpired                 = 2104,
    NoResetCode                     = 2200,
    NoResetTimestamp                = 2201,
    ResetWindowExpired              = 2202,
    DeleteByNotSpecified            = 2300,
    PasswordNotSpecified            = 2301,
    PasswordTypeNotFound            = 2400,
    CannotRemoveDefault             = 2401
}

impl ErrorCode {
    pub fn with_msg(&self, message: &str) -> VaultError {
        VaultError::new(*self, message)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VaultError {
    error_code: ErrorCode,
    message: String,
}

impl VaultError {
    pub fn new(error_code: ErrorCode, message: &str) -> Self {
        VaultError { error_code, message: message.to_string() }
    }

    pub fn error_code(&self) -> ErrorCode {
        self.error_code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<tonic::transport::Error> for VaultError {
    fn from(error: tonic::transport::Error) -> Self {
        ErrorCode::TonicStartError.with_msg(&format!("Failed to start gRPC server: {}", error))
    }
}

impl From<argon2::Error> for VaultError {
    fn from(error: argon2::Error) -> Self {
        ErrorCode::InvalidAlgorthimConfig.with_msg(&format!("Invalid configuration for algorithm: {}", error))
    }
}

impl From<argon2::password_hash::Error> for VaultError {
    fn from(error: argon2::password_hash::Error) -> Self {
        ErrorCode::HashingError.with_msg(&format!("Unable to hash password: {}", error))
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(error: serde_json::Error) -> Self {
        ErrorCode::InvalidJSON.with_msg(&format!("Unable to convert to json: {}", error))
    }
}

impl From<mongodb::error::Error> for VaultError {
    fn from(error: mongodb::error::Error) -> Self {
        // Some API changes in MongoDB here.
        // if let ErrorKind::WriteError(write_failure) = &*error.kind {
        //     if let WriteFailure::WriteError(write_error) = write_failure {
        //         if write_error.code == 11000 /* Duplicate key violation */ {
        //             return InternalError::MongoDuplicateError { cause: error.to_string() }
        //         }
        //     }
        // }
        ErrorCode::MongoDBError.with_msg( &format!("MongoDB error: {}", error))
    }
}

impl From<ValueAccessError> for VaultError {
    fn from(error: ValueAccessError) -> Self {
        ErrorCode::BSONFieldNotFound.with_msg(&format!("Unable to read BSON: {}", error))
    }
}

impl From<bson::ser::Error> for VaultError {
    fn from(error: bson::ser::Error) -> Self {
        ErrorCode::InvalidBSON.with_msg(&format!("Unable to serialise BSON: {}", error))
    }
}

impl From<bson::de::Error> for VaultError {
    fn from(error: bson::de::Error) -> Self {
        ErrorCode::InvalidBSON.with_msg(&format!("Unable to deserialise BSON: {}", error))
    }
}

impl From<JoinError> for VaultError {
    fn from(error: JoinError) -> Self {
        ErrorCode::HashThreadingIssue.with_msg(&format!("Unable to hash: {}", error))
    }
}

impl From<BcryptError> for VaultError {
    fn from(error: BcryptError) -> Self {
        ErrorCode::InvalidAlgorthimConfig.with_msg(&format!("Unable to verify: {}", error))
    }
}

impl From<pbkdf2::password_hash::Error> for VaultError {
    fn from(error: pbkdf2::password_hash::Error) -> Self {
        ErrorCode::HashingError.with_msg(&format!("Unable to hash password: {}", error))
    }
}

#[cfg(feature = "kafka")]
impl From<(KafkaError, OwnedMessage)> for VaultError {
    fn from((error, message): (KafkaError, OwnedMessage)) -> Self {
        ErrorCode::KafkaSendError.with_msg(&format!("Kafka error: {}, message: {:?}", error, message))
    }
}

///
/// Convert our internal error into a gRPC status response.
///
impl From<VaultError> for Status {
    fn from(error: VaultError) -> Self {
        use ErrorCode::*;

        let code = match &error.error_code {
            ActivePolicyNotFound    |
            HashThreadingIssue      |
            BSONFieldNotFound       |
            ConfigDocumentNotFound  |
            HashingError            |
            InvalidAlgorthimConfig  |
            InvalidBSON             |
            InvalidJSON             |
            InvalidPHCFormat        |
            KafkaSendError          |
            MongoDBError            |
            TonicStartError         |
            UnableToReadCredentials |
            UnknownAlgorithmVariant => Code::Internal,

            PasswordTypeNotFound |
            PolicyNotFound       => Code::NotFound,

            AlgorthimMandatory            |
            CannotRemoveDefault           |
            CharacterRepeatedTooManyTimes |
            DeleteByNotSpecified          |
            InvalidArgonParalellism       |
            InvalidArgonTaglength         |
            InvalidArgonVersion           |
            InvalidArgonMemorySize        |
            InvalidArgonCost              |
            InvalidBcryptCost             |
            InvalidPbkdf2Cost             |
            InvalidPbkdf2OutputLen        |
            InvalidPolicy                 |
            NotEnoughLetters              |
            NotEnoughNumbers              |
            NotEnoughSymbols              |
            NotMixedCase                  |
            NoResetCode                   |
            NoResetTimestamp              |
            PasswordContainsBannedPhrase  |
            PasswordNotSpecified          |
            PasswordTooLong               |
            PasswordTooShort              |
            PasswordUsedBefore            |
            PolicyMandatory               |
            TooManyLetters                |
            TooManyNumbers                |
            TooManySymbols => Code::InvalidArgument,

            PasswordExpired    |
            ResetWindowExpired => Code::DeadlineExceeded,

            PasswordNotFound |
            PasswordNotMatch |
            TooManyFailedAttempts => Code::Unauthenticated,
        };

        Status::with_details(code, error.message, format!("{}", error.error_code as u32).into())
    }
}