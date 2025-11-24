//! Common type definitions used throughout the application.
//!
//! This module contains shared enums and structs that define the core data structures
//! for processing modes, tasks, and results.

mod processor;
mod task;

pub use processor::{Processing, ProcessorMode};
pub use task::{Task, TaskResult};
