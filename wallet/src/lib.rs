//! Native wallet, durable state, and transfer files for Tinylayer.

#![forbid(unsafe_code)]

mod cli;
mod model;
mod services;
mod store;

pub use cli::{Cli, run};
