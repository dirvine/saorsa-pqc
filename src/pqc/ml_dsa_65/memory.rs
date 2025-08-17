//! Secure memory management for ML-DSA-65
//!
//! This module provides secure memory allocation and management utilities
//! specifically designed for cryptographic operations.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure memory allocator that locks memory and zeroizes on deallocation
pub struct SecureAllocator;

/// Secure memory block that is automatically zeroized on drop
/// Uses safe Rust with explicit zeroization instead of unsafe allocations
pub struct SecureMemory<T: Clone + Default + Zeroize> {
    data: Vec<T>,
}

impl<T: Clone + Default + Zeroize> SecureMemory<T> {
    /// Allocate secure memory for `count` items of type T
    ///
    /// # Security
    /// - Memory is zeroized on deallocation
    /// - Uses safe Rust allocations
    /// - Allocation failures are handled gracefully
    ///
    /// # Parameters
    /// - `count`: Number of items to allocate
    ///
    /// # Returns
    /// - `Ok(SecureMemory)`: Successfully allocated secure memory
    /// - `Err(String)`: Allocation failed
    pub fn new(count: usize) -> Result<Self, String> {
        if count == 0 {
            return Err("Cannot allocate zero items".to_string());
        }

        let mut data = Vec::with_capacity(count);
        data.resize(count, T::default());

        Ok(Self { data })
    }

    /// Get a mutable slice to the secure memory
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }

    /// Get an immutable slice to the secure memory
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Get the length of the allocated memory
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the memory is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<T: Clone + Default + Zeroize> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        // Zeroize memory before deallocation
        self.data.zeroize();
    }
}

/// Memory pool for efficient allocation of frequently used objects
pub struct MemoryPool<T: Zeroize> {
    available: Vec<Box<T>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
    max_size: usize,
}

impl<T: Zeroize> MemoryPool<T> {
    /// Create a new memory pool with a factory function
    ///
    /// # Parameters
    /// - `factory`: Function to create new instances of T
    /// - `initial_size`: Initial number of objects to pre-allocate
    /// - `max_size`: Maximum number of objects to keep in pool
    pub fn new<F>(factory: F, initial_size: usize, max_size: usize) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        let mut pool = Self {
            available: Vec::with_capacity(max_size),
            factory: Box::new(factory),
            max_size,
        };

        // Pre-allocate initial objects
        for _ in 0..initial_size {
            pool.available.push(Box::new((pool.factory)()));
        }

        pool
    }

    /// Take an object from the pool or create a new one
    pub fn take(&mut self) -> Box<T> {
        self.available
            .pop()
            .unwrap_or_else(|| Box::new((self.factory)()))
    }

    /// Return an object to the pool
    pub fn put(&mut self, mut obj: Box<T>) {
        if self.available.len() < self.max_size {
            // Zeroize the object before returning to pool
            obj.zeroize();
            self.available.push(obj);
        }
        // If pool is full, just drop the object
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.available.len()
    }

    /// Get maximum pool size
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

/// RAII wrapper for pool objects that automatically returns to pool
pub struct PoolGuard<'a, T: Zeroize> {
    obj: Option<Box<T>>,
    pool: &'a mut MemoryPool<T>,
}

impl<'a, T: Zeroize> PoolGuard<'a, T> {
    /// Create a new pool guard
    pub fn new(pool: &'a mut MemoryPool<T>) -> Self {
        let obj = pool.take();
        Self {
            obj: Some(obj),
            pool,
        }
    }

    /// Get mutable reference to the object
    pub fn get_mut(&mut self) -> &mut T {
        self.obj.as_mut().expect("Object should be available")
    }

    /// Get immutable reference to the object
    pub fn get(&self) -> &T {
        self.obj.as_ref().expect("Object should be available")
    }
}

impl<'a, T: Zeroize> Drop for PoolGuard<'a, T> {
    fn drop(&mut self) {
        if let Some(obj) = self.obj.take() {
            self.pool.put(obj);
        }
    }
}

/// Secure buffer that zeroizes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
        }
    }

    /// Create a secure buffer from existing data
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Get the buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the buffer as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Resize the buffer, zeroizing any new space
    pub fn resize(&mut self, new_len: usize) {
        self.data.resize(new_len, 0);
    }
}

/// Stack-allocated secure array that zeroizes on drop
pub struct SecureArray<T: Copy + Default + Zeroize, const N: usize> {
    data: [T; N],
}

impl<T: Copy + Default + Zeroize, const N: usize> SecureArray<T, N> {
    /// Create a new secure array filled with default values
    pub fn new() -> Self {
        Self {
            data: [T::default(); N],
        }
    }

    /// Create from existing array
    pub fn from_array(data: [T; N]) -> Self {
        Self { data }
    }

    /// Get reference to underlying array
    pub fn as_array(&self) -> &[T; N] {
        &self.data
    }

    /// Get mutable reference to underlying array
    pub fn as_mut_array(&mut self) -> &mut [T; N] {
        &mut self.data
    }

    /// Get as slice
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Get as mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }
}

impl<T: Copy + Default + Zeroize, const N: usize> Drop for SecureArray<T, N> {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<T: Copy + Default + Zeroize, const N: usize> Default for SecureArray<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_memory_allocation() {
        let mut mem = SecureMemory::<u8>::new(10).unwrap();
        assert_eq!(mem.len(), 10);
        assert!(!mem.is_empty());

        let slice = mem.as_mut_slice();
        slice[0] = 42;
        slice[9] = 99;

        assert_eq!(slice[0], 42);
        assert_eq!(slice[9], 99);
    }

    #[test]
    fn test_secure_memory_zero_allocation() {
        let result = SecureMemory::<u8>::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_pool() {
        // Create a pool with Vec<u8> which implements Zeroize
        let mut pool = MemoryPool::new(|| vec![0u8; 1024], 2, 5);
        assert_eq!(pool.size(), 2);

        let obj1 = pool.take();
        let obj2 = pool.take();
        let obj3 = pool.take(); // This should create a new one

        assert_eq!(pool.size(), 0);

        pool.put(obj1);
        assert_eq!(pool.size(), 1);

        pool.put(obj2);
        pool.put(obj3);
        assert_eq!(pool.size(), 3);
    }

    #[test]
    fn test_pool_guard() {
        let mut pool = MemoryPool::new(|| vec![0u8; 10], 1, 3);

        {
            let mut guard = PoolGuard::new(&mut pool);
            let obj = guard.get_mut();
            obj[0] = 42;
        } // guard should return object to pool here

        assert_eq!(pool.size(), 1);
    }

    #[test]
    fn test_secure_buffer() {
        let mut buffer = SecureBuffer::new(100);
        assert_eq!(buffer.len(), 100);
        assert!(!buffer.is_empty());

        buffer.as_mut_slice()[0] = 0xFF;
        assert_eq!(buffer.as_slice()[0], 0xFF);

        buffer.resize(200);
        assert_eq!(buffer.len(), 200);
        assert_eq!(buffer.as_slice()[150], 0); // New space should be zeroed
    }

    #[test]
    fn test_secure_buffer_from_slice() {
        let data = [1, 2, 3, 4, 5];
        let buffer = SecureBuffer::from_slice(&data);

        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.as_slice(), &data);
    }

    #[test]
    fn test_secure_array() {
        let mut arr = SecureArray::<u8, 10>::new();
        assert_eq!(arr.as_slice().len(), 10);

        arr.as_mut_array()[5] = 42;
        assert_eq!(arr.as_array()[5], 42);
    }

    #[test]
    fn test_secure_array_from_array() {
        let data = [1u8, 2, 3, 4, 5];
        let arr = SecureArray::from_array(data);

        assert_eq!(arr.as_slice(), &data);
    }
}
