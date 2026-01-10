//! This module provides a global, lazily-initialized buffer pool for `StreamChunk` objects.
//!
//! The buffer pool is designed to optimize memory allocation and reuse for `StreamChunk`s,
//! which are used for receiving stream data. It can be initialized with a specific maximum
//! memory size at application startup, or it will lazily initialize with a default size
//! upon first access.
//!
//! # Usage
//!
//! To explicitly initialize the buffer pool with a custom maximum memory size (in bytes),
//! call the `init` function once at the beginning of your application:
//!
//! ```
//! use quiceh::bufpool;
//!
//! // Initialize the buffer pool to a maximum of 2 GiB with 64KiB buffers
//! bufpool::init(2 * 1_073_741_824, 65_536);
//! ```
//!
//! If `init` is not called, the buffer pool will be automatically initialized with a default
//! size (1 GiB) when `pool_or_default()` is first invoked.
//!
//! To access the buffer pool, use `pool()` (which panics if not initialized) or
//! `pool_or_default()` (which initializes it with a default if necessary).
//!
//! ```
//! use quiceh::bufpool;
//!
//! // Get a reference to the buffer pool (will initialize with default if not already done)
//! let my_pool = bufpool::pool_or_default();
//!
//! // Get a reference to the buffer pool (will panic if not already initialized)
//! // bufpool::init(1024); // Must be called first for this to not panic
//! // let my_pool_strict = bufpool::pool();
//! ```

use crate::stream::StreamChunk;
use crate::DEFAULT_CHUNK_LEN;
use buffer_pool::Pool;
use once_cell::sync::OnceCell;

// Default memory pool size: 1GiB
const MAX_MEMORY_POOL: usize = 1_073_741_824;
const SHARDS: usize = 8;

type BufPool = Pool<SHARDS, StreamChunk>;
static POOL: OnceCell<BufPool> = OnceCell::new();

/// Initializes the buffer pool with a specific size.
///
/// This function should be called once at the start of the application.
///
/// # Panics
///
/// Panics if the pool is already initialized.
pub fn init(max_memory: usize, chunk_len: usize) {
    let pool = BufPool::new(max_memory / chunk_len, DEFAULT_CHUNK_LEN);
    POOL.set(pool).expect("pool already initialized");
}

/// Returns a reference to the buffer pool.
///
/// # Panics
///
/// Panics if the pool is not initialized.
pub fn pool() -> &'static BufPool {
    POOL.get().expect("pool not initialized")
}

/// Returns a reference to the buffer pool, initializing it with a default
/// size if it hasn't been initialized yet.
pub fn pool_or_default() -> &'static BufPool {
    POOL.get_or_init(|| {
        BufPool::new(
            MAX_MEMORY_POOL / DEFAULT_CHUNK_LEN,
            DEFAULT_CHUNK_LEN,
        )
    })
}

