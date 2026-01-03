//! Memory locking utilities
//!
//! This module provides utilities for locking memory pages to prevent
//! sensitive data from being swapped to disk. Uses mlock/munlock syscalls.
//!
//! SECURITY NOTE: Memory locking is a defense-in-depth measure. It prevents
//! private keys from being written to swap, which could persist after the
//! process exits and be recovered by an attacker.

use crate::errors::{LockSignError, Result};
use std::ptr;
use tracing::{debug, warn};
use nix::libc;
/// Check if we can lock memory (requires appropriate privileges or rlimits)
pub fn can_lock_memory() -> bool {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::resource::{getrlimit, Resource};

        match getrlimit(Resource::RLIMIT_MEMLOCK) {
            Ok((soft, _hard)) => soft > 0, // Soft limit > 0
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Lock a memory region to prevent it from being swapped
///
/// # Safety
/// The memory region must be valid and properly aligned
pub unsafe fn lock_memory(ptr: *const u8, len: usize) -> Result<()> {
    if ptr.is_null() || len == 0 {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        use nix::sys::mman::mlock;

        // Get system page size using libc::sysconf
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let addr = ptr as usize;
        let aligned_addr = addr & !(page_size - 1);
        let offset = addr - aligned_addr;
        let aligned_len = (len + offset + page_size - 1) & !(page_size - 1);

        let result = mlock(aligned_addr as *const libc::c_void, aligned_len);

        match result {
            Ok(_) => {
                debug!("Locked {} bytes of memory at {:p}", aligned_len, ptr);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to lock memory: {}", e);
                Err(LockSignError::MemoryLockFailed(e.to_string()))
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let result = libc::mlock(ptr as *const libc::c_void, len);
        if result == 0 {
            debug!("Locked {} bytes of memory at {:p}", len, ptr);
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            warn!("Failed to lock memory: {}", err);
            Err(LockSignError::MemoryLockFailed(err.to_string()))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        warn!("Memory locking not supported on this platform");
        Ok(())
    }
}

/// Unlock a previously locked memory region
///
/// # Safety
/// The memory region must have been previously locked with lock_memory
pub unsafe fn unlock_memory(ptr: *const u8, len: usize) -> Result<()> {
    if ptr.is_null() || len == 0 {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        use nix::sys::mman::munlock;

        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let addr = ptr as usize;
        let aligned_addr = addr & !(page_size - 1);
        let offset = addr - aligned_addr;
        let aligned_len = (len + offset + page_size - 1) & !(page_size - 1);

        let result = munlock(aligned_addr as *const libc::c_void, aligned_len);

        match result {
            Ok(_) => {
                debug!("Unlocked {} bytes of memory at {:p}", aligned_len, ptr);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to unlock memory: {}", e);
                Err(LockSignError::MemoryLockFailed(e.to_string()))
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let result = libc::munlock(ptr as *const libc::c_void, len);
        if result == 0 {
            debug!("Unlocked {} bytes of memory at {:p}", len, ptr);
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            warn!("Failed to unlock memory: {}", err);
            Err(LockSignError::MemoryLockFailed(err.to_string()))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

/// A memory region that is locked to prevent swapping
/// Automatically unlocks and zeros on drop
pub struct LockedMemory {
    data: Vec<u8>,
    locked: bool,
}

impl LockedMemory {
    /// Allocate and lock a new memory region
    pub fn new(size: usize) -> Result<Self> {
        let mut data = vec![0u8; size];

        let locked = unsafe {
            match lock_memory(data.as_ptr(), data.len()) {
                Ok(_) => true,
                Err(e) => {
                    warn!("Could not lock memory, continuing without: {}", e);
                    false
                }
            }
        };

        Ok(Self { data, locked })
    }

    /// Create locked memory from existing data
    pub fn from_vec(data: Vec<u8>) -> Result<Self> {
        let locked = unsafe {
            match lock_memory(data.as_ptr(), data.len()) {
                Ok(_) => true,
                Err(e) => {
                    warn!("Could not lock memory, continuing without: {}", e);
                    false
                }
            }
        };

        Ok(Self { data, locked })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for LockedMemory {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();

        if self.locked {
            unsafe {
                let _ = unlock_memory(self.data.as_ptr(), self.data.len());
            }
        }
    }
}

/// Set up memory protection for the process
/// Call this early in main()
pub fn setup_memory_protection() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::resource::{setrlimit, Resource};

        if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
            warn!("Could not disable core dumps: {}", e);
        } else {
            debug!("Core dumps disabled");
        }
    }

    if can_lock_memory() {
        debug!("Memory locking is available");
    } else {
        warn!("Memory locking may not be available - consider increasing RLIMIT_MEMLOCK");
    }

    Ok(())
}
