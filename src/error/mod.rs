// Copyright (c) 2016-2020 Memgraph Ltd. [https://memgraph.com]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::Value;
use std::fmt;
use thiserror::Error;

/// Error returned by using connection.
#[derive(Error, Debug)]
pub enum MgError {
    #[error("{message}")]
    Generic { message: String },
    #[error("Failed to convert value {value} into {typename}")]
    ConversionError {
        value: Value,
        typename: &'static str,
    },
    #[error("Record does not have exactly 1 value")]
    RecordConversionError,
}

impl MgError {
    // TODO: Consider deprecating in favor of typed errors
    pub fn new(message: String) -> MgError {
        MgError::Generic { message }
    }
}
