//! yara-backend — Rule loading and scanning facade backed by yara-x.
//!
//! Owns the YARA engine surface for MalChela's analysis tools. Caller crates
//! import [`YaraBackend`], [`Match`], [`MatchedString`], [`ScanReport`],
//! [`Error`], and [`Result`] from this crate rather than depending on `yara`
//! or `yara_x` directly. This keeps the engine choice as a single point of
//! change.
//!
//! See `README.md` for usage examples.

pub use backend::YaraBackend;
pub use error::{Error, Result};
pub use match_types::{Match, MatchedString, ScanReport};

mod audit;
mod backend;
mod cache;
mod compile;
mod error;
mod match_types;
mod scan;
