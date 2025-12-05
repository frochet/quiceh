use crate::stream::StreamChunk;
use crate::DEFAULT_CHUNK_LEN;
use buffer_pool::Pool;

// TODO make this configurable.
const MAX_MEMORY_POOL: usize = 1_073_741_824; // 1GiB
const SHARDS: usize = 8;
type BufPool = Pool<SHARDS, StreamChunk>;

pub static POOL: BufPool = BufPool::new(
    MAX_MEMORY_POOL / DEFAULT_CHUNK_LEN,
    DEFAULT_CHUNK_LEN as usize,
);
