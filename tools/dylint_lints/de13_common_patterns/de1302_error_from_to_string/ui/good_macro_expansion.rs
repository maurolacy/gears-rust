// Created: 2026-04-22 by Constructor Tech
// Updated: 2026-04-22 by Constructor Tech
#![allow(dead_code)]

use std::fmt;

// Negative case: `.to_string()` calls produced by macro expansion are
// ignored. This covers derive macros, tracing/format macros, `?` desugaring,
// and anything else that might synthesize a stringification the user didn't
// literally write.

#[derive(Debug)]
struct DatabaseError(String);

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DatabaseError {}

#[derive(Debug)]
struct AppError(String);

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

// A user macro whose expansion includes `.to_string()` on an error.
macro_rules! render_err {
    ($e:expr) => {
        $e.to_string() // Should not trigger DE1302 - to_string
    };
}

impl From<DatabaseError> for AppError {
    fn from(e: DatabaseError) -> Self {
        // The `.to_string()` lives inside the macro expansion, so its span
        // carries `from_expansion() == true` and the lint skips it.
        AppError(render_err!(e))
    }
}

fn main() {}
