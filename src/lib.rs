//! Sandbox — a minimal Linux container manager.
//!
//! This module exposes internals for integration testing.

// Many items are currently only used by the binary or tests.
// As the API stabilizes, dead_code will be removed.
#![allow(dead_code)]

pub mod cgroup;
pub mod container;
pub mod error;
pub mod namespace;
pub mod net;
pub mod protocol;
pub mod rootfs;
pub mod security;
pub mod storage;
pub mod sys;
