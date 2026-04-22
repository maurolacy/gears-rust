// Created: 2026-04-22 by Constructor Tech
// Updated: 2026-04-22 by Constructor Tech
#![allow(dead_code)]

use std::fmt;

// Positive case for the TryFrom::Error gate: source and target are both
// plain non-error types, but the associated `type Error = MyErr` implements
// `std::error::Error`. The body stringifies a locally-constructed `MyErr`
// before wrapping it — that's a chain loss on the assoc Error type, which
// the tightened receiver check also accepts.

#[derive(Debug)]
struct MyErr {
    msg: String,
}

impl fmt::Display for MyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for MyErr {}

struct PlainData(u32);
struct PlainOutput(u32);

impl TryFrom<PlainData> for PlainOutput {
    type Error = MyErr;

    fn try_from(value: PlainData) -> Result<Self, Self::Error> {
        if value.0 == 0 {
            let inner = MyErr { msg: "zero not allowed".into() };
            // Should trigger DE1302 - to_string
            return Err(MyErr { msg: inner.to_string() });
        }
        Ok(PlainOutput(value.0))
    }
}

fn main() {}
