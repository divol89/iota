// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota::iota_authenticator_functions;

use iota::authenticator_function::{Self, AuthenticatorFunctionRefV1};
use iota::public_key_field;
use std::ascii;

// === Errors ===

#[error(code = 0)]
const EPublicKeyMissing: vector<u8> = b"Public key missing.";

// === Constants ===

// === Structs ===

// === Public Functions ===

/// Returns an `AuthenticatorFunctionRefV1` instance for the built-in ed25519 authenticator function.
public fun ed25519_authenticator_function_ref_v1<Account: key>(
    account: &UID,
): AuthenticatorFunctionRefV1<Account> {
    assert!(public_key_field::has_public_key(account), EPublicKeyMissing);

    authenticator_function::create_auth_function_ref_v1_inner(
        @0x2,
        ascii::string(b"iota_authenticator_functions"),
        ascii::string(b"ed25519_authenticator_function_ref_v1"),
    )
}

/// Returns an `AuthenticatorFunctionRefV1` instance for the built-in secp256k1 authenticator function.
public fun secp256k1_authenticator_function_ref_v1<Account: key>(
    account: &UID,
): AuthenticatorFunctionRefV1<Account> {
    assert!(public_key_field::has_public_key(account), EPublicKeyMissing);

    authenticator_function::create_auth_function_ref_v1_inner(
        @0x2,
        ascii::string(b"iota_authenticator_functions"),
        ascii::string(b"secp256k1_authenticator_function_ref_v1"),
    )
}

/// Returns an `AuthenticatorFunctionRefV1` instance for the built-in secp256r1 authenticator function.
public fun secp256r1_authenticator_function_ref_v1<Account: key>(
    account: &UID,
): AuthenticatorFunctionRefV1<Account> {
    assert!(public_key_field::has_public_key(account), EPublicKeyMissing);

    authenticator_function::create_auth_function_ref_v1_inner(
        @0x2,
        ascii::string(b"iota_authenticator_functions"),
        ascii::string(b"secp256r1_authenticator_function_ref_v1"),
    )
}

// === View Functions ===

// === Admin Functions ===

// === Package Functions ===

// === Private Functions ===

// === Test Functions ===
