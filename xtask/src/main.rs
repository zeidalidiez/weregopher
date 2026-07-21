//! Repository automation command-line entry point.

#![forbid(unsafe_code)]

use std::env;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let repository_root = env::current_dir().context("failed to determine repository root")?;
    xtask::run(env::args().skip(1), &repository_root)
}
