//! Global memory allocator configuration.
//!
//! This module configures the global memory allocator for the application.
//! We use `mimalloc` (Microsoft's high-performance allocator) instead of the
//! system allocator to improve performance, particularly for the highly concurrent
//! workload typical of file encryption/decryption tasks.
//!
//! `mimalloc` excels in multi-threaded environments by minimizing lock contention
//! and fragmentation, which is critical for our worker pool architecture where
//! large buffers are frequently allocated and deallocated across threads.

use mimalloc::MiMalloc;

/// The global allocator instance.
///
/// We use the default `MiMalloc` configuration. This static instance is
/// registered as the `#[global_allocator]`, replacing the standard library's
/// default system allocator.
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
