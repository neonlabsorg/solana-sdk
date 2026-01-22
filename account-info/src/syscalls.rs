//! Dynamic account syscalls.
#![cfg(target_os = "solana")]

use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_define_syscall::definitions::{
    sol_account_data_read, sol_account_data_slice, sol_account_data_write,
    sol_account_data_len, sol_account_lamports_get, sol_account_lamports_set,
    sol_account_realloc, sol_load_account,
};

/// Load an account into the transaction context and return its index.
#[inline]
pub fn load_account(pubkey: &Pubkey, is_writable: bool) -> u64 {
    let mut index: u64 = 0;
    unsafe {
        sol_load_account(
            pubkey.as_ref().as_ptr(),
            is_writable as u64,
            &mut index as *mut u64,
        );
    }
    index
}

/// Load an account and return an error if the syscall fails.
#[inline]
pub fn load_account_checked(pubkey: &Pubkey, is_writable: bool) -> Result<u64, ProgramError> {
    let mut index: u64 = 0;
    let ret = unsafe {
        sol_load_account(
            pubkey.as_ref().as_ptr(),
            is_writable as u64,
            &mut index as *mut u64,
        )
    };
    if ret == 0 {
        Ok(index)
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Read account data into `dst` starting at `offset`.
#[inline]
pub fn account_data_read(account_index: u64, offset: usize, dst: &mut [u8]) {
    unsafe {
        sol_account_data_read(
            account_index,
            offset as u64,
            dst.as_mut_ptr(),
            dst.len() as u64,
        );
    }
}

/// Write `src` into account data starting at `offset`.
#[inline]
pub fn account_data_write(account_index: u64, offset: usize, src: &[u8]) {
    unsafe {
        sol_account_data_write(
            account_index,
            offset as u64,
            src.as_ptr(),
            src.len() as u64,
        );
    }
}

/// Get account data length.
#[inline]
pub fn account_data_len(account_index: u64) -> Result<u64, ProgramError> {
    let mut len: u64 = 0;
    let ret = unsafe { sol_account_data_len(account_index, &mut len as *mut u64) };
    if ret == 0 {
        Ok(len)
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Map a window of account data into program memory (read-only).
#[inline]
pub fn account_data_slice(
    account_index: u64,
    offset: usize,
    len: usize,
) -> Result<*const u8, ProgramError> {
    let mut addr: u64 = 0;
    let ret = unsafe {
        sol_account_data_slice(
            account_index,
            offset as u64,
            len as u64,
            0,
            &mut addr as *mut u64,
        )
    };
    if ret == 0 {
        Ok(addr as *const u8)
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Map a window of account data into program memory (writable).
#[inline]
pub fn account_data_slice_mut(
    account_index: u64,
    offset: usize,
    len: usize,
) -> Result<*mut u8, ProgramError> {
    let mut addr: u64 = 0;
    let ret = unsafe {
        sol_account_data_slice(
            account_index,
            offset as u64,
            len as u64,
            1,
            &mut addr as *mut u64,
        )
    };
    if ret == 0 {
        Ok(addr as *mut u8)
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Get lamports for a dynamic account.
#[inline]
pub fn account_lamports_get(account_index: u64) -> u64 {
    let mut lamports: u64 = 0;
    unsafe {
        sol_account_lamports_get(account_index, &mut lamports as *mut u64);
    }
    lamports
}

/// Set lamports for a dynamic account.
#[inline]
pub fn account_lamports_set(account_index: u64, lamports: u64) {
    unsafe {
        sol_account_lamports_set(account_index, lamports);
    }
}

/// Resize account data.
#[inline]
pub fn account_realloc(account_index: u64, new_len: usize, zero_init: bool) {
    unsafe {
        sol_account_realloc(account_index, new_len as u64, zero_init as u64);
    }
}
