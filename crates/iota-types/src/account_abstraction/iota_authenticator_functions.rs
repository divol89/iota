use move_core_types::{ident_str, identifier::IdentStr};

use crate::{
    IOTA_FRAMEWORK_ADDRESS,
    account_abstraction::authenticator_function::AuthenticatorFunctionRefV1,
    crypto::SignatureScheme,
};

pub const IOTA_AUTHENTICATOR_FUNCTIONS_MODULE_NAME: &IdentStr =
    ident_str!("iota_authenticator_functions");

pub const ED25519_AUTHENTICATOR_FUNCTION_V1_NAME: &IdentStr =
    ident_str!("ed25519_authenticator_function_ref_v1");
pub const SECP256K1_AUTHENTICATOR_FUNCTION_V1_NAME: &IdentStr =
    ident_str!("secp256k1_authenticator_function_ref_v1");
pub const SECP256R1_AUTHENTICATOR_FUNCTION_V1_NAME: &IdentStr =
    ident_str!("secp256r1_authenticator_function_ref_v1");

/// Returns an authentication function that references the built-in ed25519
/// authenticator.
pub fn ed25519_authenticator_function_ref_v1() -> AuthenticatorFunctionRefV1 {
    AuthenticatorFunctionRefV1 {
        package: IOTA_FRAMEWORK_ADDRESS.into(),
        module: IOTA_AUTHENTICATOR_FUNCTIONS_MODULE_NAME.to_string(),
        function: ED25519_AUTHENTICATOR_FUNCTION_V1_NAME.to_string(),
    }
}

/// Returns an authentication function that references the built-in secp256k1
/// authenticator.
pub fn secp256k1_authenticator_function_ref_v1() -> AuthenticatorFunctionRefV1 {
    AuthenticatorFunctionRefV1 {
        package: IOTA_FRAMEWORK_ADDRESS.into(),
        module: IOTA_AUTHENTICATOR_FUNCTIONS_MODULE_NAME.to_string(),
        function: SECP256K1_AUTHENTICATOR_FUNCTION_V1_NAME.to_string(),
    }
}

/// Returns an authentication function that references the built-in secp256r1
/// authenticator.
pub fn secp256r1_authenticator_function_ref_v1() -> AuthenticatorFunctionRefV1 {
    AuthenticatorFunctionRefV1 {
        package: IOTA_FRAMEWORK_ADDRESS.into(),
        module: IOTA_AUTHENTICATOR_FUNCTIONS_MODULE_NAME.to_string(),
        function: SECP256R1_AUTHENTICATOR_FUNCTION_V1_NAME.to_string(),
    }
}

/// If the given authenticator function reference corresponds to a built-in
/// authenticator, returns the corresponding signature scheme. Otherwise,
/// returns None.
pub fn builtin_signature_scheme(
    authenticator_function_ref: &AuthenticatorFunctionRefV1,
) -> Option<SignatureScheme> {
    if authenticator_function_ref == &ed25519_authenticator_function_ref_v1() {
        Some(SignatureScheme::ED25519)
    } else if authenticator_function_ref == &secp256k1_authenticator_function_ref_v1() {
        Some(SignatureScheme::Secp256k1)
    } else if authenticator_function_ref == &secp256r1_authenticator_function_ref_v1() {
        Some(SignatureScheme::Secp256r1)
    } else {
        None
    }
}
