// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota::public_key_field;

use iota::dynamic_field as df;

// === Errors ===

#[error(code = 0)]
const EPublicKeyAlreadyAttached: vector<u8> = b"Public key already attached.";
#[error(code = 1)]
const EPublicKeyMissing: vector<u8> = b"Public key missing.";

// === Constants ===

// === Structs ===

/// Dynamic field key, where the system will look for a potential public key.
public struct PublicKeyFieldName has copy, drop, store {}

// === Public Functions ===

/// Attach public key data to the account with the provided `public_key`.
public fun attach_public_key(account_id: &mut UID, public_key: vector<u8>) {
    assert!(!has_public_key(account_id), EPublicKeyAlreadyAttached);

    // TODO: add the `public_key` array validation.

    df::add(account_id, public_key_field_name(), public_key)
}

/// Detach public key data from the account.
public fun detach_public_key(account_id: &mut UID): vector<u8> {
    assert!(has_public_key(account_id), EPublicKeyMissing);

    df::remove(account_id, public_key_field_name())
}

/// Update the public key attached to the account.
public fun rotate_public_key(account_id: &mut UID, public_key: vector<u8>): vector<u8> {
    assert!(has_public_key(account_id), EPublicKeyMissing);

    // TODO: add the `public_key` array validation.

    let df_name = public_key_field_name();

    let prev_public_key = df::remove(account_id, df_name);
    df::add(account_id, df_name, public_key);
    prev_public_key
}

// === View Functions ===

/// An utility function to check if the account has a public key set.
public fun has_public_key(account_id: &UID): bool {
    df::exists_(account_id, public_key_field_name())
}

/// An utility function to borrow the account-related public key.
public fun borrow_public_key(account_id: &UID): &vector<u8> {
    df::borrow(account_id, public_key_field_name())
}

// === Admin Functions ===

// === Package Functions ===

/// An utility function to construct the dynamic field name for the public key field.
fun public_key_field_name(): PublicKeyFieldName {
    PublicKeyFieldName {}
}

// === Private Functions ===

// === Test Functions ===
