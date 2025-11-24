//! High-performance streaming encryption/decryption pipeline.
//!
//! This module implements a concurrent, pipelined architecture for processing large files.
//! It handles reading, processing (encryption/decryption), and writing in parallel stages
//! to maximize throughput.
//!
//! # Architecture
//!
//! The pipeline consists of three main stages:
//!
//! 1.  **Reader**: Reads chunks of data from the input stream (`StreamReader`).
//! 2.  **Worker**: Processes chunks in parallel using a thread pool (`ChunkWorker`).
//! 3.  **Writer**: Writes processed chunks to the output stream in correct order (`StreamWriter`).
//!
//! # Key Components
//!
//! -   `Pipeline`: The main orchestrator that manages the stages and concurrency.
//! -   `BufferPool`: A memory pool to reuse buffers and minimize allocations.
//! -   `ReorderBuffer`: Ensures chunks are written in the correct sequence even if processed out of order.

pub mod buffer;
pub mod pipeline;
pub mod pool;
pub mod reader;
pub mod worker;
pub mod writer;

pub use pipeline::Pipeline;
