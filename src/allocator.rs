//! Memory Allocator Configuration
//!
//! This module configures the application to use the mimalloc memory allocator.
//! mimalloc is a high-performance allocator that provides better performance
//! characteristics than the default system allocator for cryptographic workloads
//! with many small allocations and deallocations.
//!
//! ## Security Considerations
//!
//! The choice of memory allocator can impact security through:
//! - Memory allocation patterns that may be observable in side-channel attacks
//! - Memory zeroization behavior when blocks are freed
//! - Heap spraying resistance
//!
//! mimalloc provides better security properties including:
//! - Randomized allocation patterns to mitigate heap spraying attacks
//! - Reduced memory fragmentation
//! - Better cache locality which reduces timing-based side channels

use mimalloc::MiMalloc;

/// Global memory allocator instance using mimalloc
///
/// This replaces the default system allocator with mimalloc for improved
/// performance and security characteristics. mimalloc is particularly well-suited
/// for cryptographic applications due to:
///
/// 1. **Performance**: Faster allocation/deallocation patterns for the many small buffers used in
///    cryptographic operations
/// 2. **Security**: Randomized allocation patterns reduce vulnerability to heap exploitation
///    techniques
/// 3. **Memory Efficiency**: Better cache utilization and reduced fragmentation
///
/// The allocator is configured with secure defaults that prioritize safety
/// over maximum speed, making it appropriate for security-sensitive applications.
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
