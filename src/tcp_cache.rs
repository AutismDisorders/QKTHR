use crate::response::Response;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// TcpCache stores responses for reuse, keyed by connection string (e.g., "host:port").
#[derive(Debug, Clone)]
pub struct TcpCache {
    inner: Arc<RwLock<HashMap<String, Response>>>,
}

impl TcpCache {
    /// Create a new empty TcpCache.
    pub fn new() -> Self {
        TcpCache {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert a response for the given key.
    pub fn insert(&self, key: String, response: Response) {
        let mut cache = self.inner.write().unwrap();
        cache.insert(key, response);
    }

    /// Get a response by key, if it exists.
    pub fn get(&self, key: &str) -> Option<Response> {
        let cache = self.inner.read().unwrap();
        cache.get(key).cloned()
    }

    /// Remove a response by key.
    pub fn remove(&self, key: &str) -> Option<Response> {
        let mut cache = self.inner.write().unwrap();
        cache.remove(key)
    }

    /// Clear the entire cache.
    pub fn clear(&self) {
        let mut cache = self.inner.write().unwrap();
        cache.clear();
    }

    /// Check if the cache contains a key.
    pub fn contains_key(&self, key: &str) -> bool {
        let cache = self.inner.read().unwrap();
        cache.contains_key(key)
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        let cache = self.inner.read().unwrap();
        cache.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        let cache = self.inner.read().unwrap();
        cache.is_empty()
    }
}

impl Default for TcpCache {
    fn default() -> Self {
        Self::new()
    }
}
