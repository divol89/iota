// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use move_core_types::{ident_str, identifier::IdentStr, language_storage::StructTag};
use serde::{Deserialize, Serialize};

use crate::IOTA_FRAMEWORK_ADDRESS;

pub const IOTA_PUBLIC_KEY_FIELD_MODULE_NAME: &IdentStr = ident_str!("public_key_field");
pub const PUBLIC_KEY_FIELD_NAME_STRUCT_NAME: &IdentStr = ident_str!("PublicKeyFieldName");

#[derive(Debug, Default, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PublicKeyFieldName {
    // This field is required to make a Rust struct compatible with an empty Move one.
    // An empty Move struct contains a 1-byte dummy bool field because empty fields are not
    // allowed in the bytecode.
    dummy_field: bool,
}

impl PublicKeyFieldName {
    pub fn tag() -> StructTag {
        StructTag {
            address: IOTA_FRAMEWORK_ADDRESS,
            module: IOTA_PUBLIC_KEY_FIELD_MODULE_NAME.to_owned(),
            name: PUBLIC_KEY_FIELD_NAME_STRUCT_NAME.to_owned(),
            type_params: Vec::new(),
        }
    }

    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self).unwrap()
    }
}
