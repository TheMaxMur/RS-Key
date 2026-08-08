// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP status codes. The CTAPHID_CBOR response is one status byte followed,
//! on success, by the CBOR payload.

/// Success — `CTAP2_OK`.
pub const CTAP2_OK: u8 = 0x00;

/// A CTAP error returned as the response's status byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapError {
    InvalidCommand = 0x01,         // CTAP1_ERR_INVALID_COMMAND
    InvalidParameter = 0x02,       // CTAP1_ERR_INVALID_PARAMETER
    InvalidLength = 0x03,          // CTAP1_ERR_INVALID_LENGTH
    InvalidSeq = 0x04,             // CTAP1_ERR_INVALID_SEQ (large-blob fragment)
    CborUnexpectedType = 0x11,     // CTAP2_ERR_CBOR_UNEXPECTED_TYPE
    InvalidCbor = 0x12,            // CTAP2_ERR_INVALID_CBOR
    MissingParameter = 0x14,       // CTAP2_ERR_MISSING_PARAMETER
    LimitExceeded = 0x15,          // CTAP2_ERR_LIMIT_EXCEEDED
    LargeBlobStorageFull = 0x18,   // CTAP2_ERR_LARGE_BLOB_STORAGE_FULL
    CredentialExcluded = 0x19,     // CTAP2_ERR_CREDENTIAL_EXCLUDED
    Processing = 0x21,             // CTAP2_ERR_PROCESSING
    InvalidCredential = 0x22,      // CTAP2_ERR_INVALID_CREDENTIAL
    UnsupportedAlgorithm = 0x26,   // CTAP2_ERR_UNSUPPORTED_ALGORITHM
    OperationDenied = 0x27,        // CTAP2_ERR_OPERATION_DENIED
    KeyStoreFull = 0x28,           // CTAP2_ERR_KEY_STORE_FULL
    UnsupportedOption = 0x2b,      // CTAP2_ERR_UNSUPPORTED_OPTION
    InvalidOption = 0x2c,          // CTAP2_ERR_INVALID_OPTION
    KeepAliveCancel = 0x2d,        // CTAP2_ERR_KEEPALIVE_CANCEL (CTAPHID_CANCEL)
    NoCredentials = 0x2e,          // CTAP2_ERR_NO_CREDENTIALS
    UserActionTimeout = 0x2f,      // CTAP2_ERR_USER_ACTION_TIMEOUT (button wait)
    NotAllowed = 0x30,             // CTAP2_ERR_NOT_ALLOWED
    PinInvalid = 0x31,             // CTAP2_ERR_PIN_INVALID
    PinBlocked = 0x32,             // CTAP2_ERR_PIN_BLOCKED
    PinAuthInvalid = 0x33,         // CTAP2_ERR_PIN_AUTH_INVALID
    PinAuthBlocked = 0x34,         // CTAP2_ERR_PIN_AUTH_BLOCKED
    PinNotSet = 0x35,              // CTAP2_ERR_PIN_NOT_SET
    PuatRequired = 0x36,           // CTAP2_ERR_PUAT_REQUIRED (PIN required)
    PinPolicyViolation = 0x37,     // CTAP2_ERR_PIN_POLICY_VIOLATION
    RequestTooLarge = 0x39,        // CTAP2_ERR_REQUEST_TOO_LARGE
    UvBlocked = 0x3c,              // CTAP2_ERR_UV_BLOCKED (built-in UV retries exhausted)
    IntegrityFailure = 0x3d,       // CTAP2_ERR_INTEGRITY_FAILURE (large-blob hash)
    InvalidSubcommand = 0x3e,      // CTAP2_ERR_INVALID_SUBCOMMAND (config vendor id)
    UvInvalid = 0x3f,              // CTAP2_ERR_UV_INVALID
    UnauthorizedPermission = 0x40, // CTAP2_ERR_UNAUTHORIZED_PERMISSION
    Other = 0x7f,                  // CTAP1_ERR_OTHER
    ExtensionFirst = 0xe0,         // CTAP2_ERR_EXTENSION_FIRST (hmac-secret salt MAC)
}

impl CtapError {
    /// The status byte for this error.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A CTAP handler result: the number of CBOR bytes written on success.
pub type CtapResult = core::result::Result<usize, CtapError>;
