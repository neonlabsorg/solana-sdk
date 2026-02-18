//! Dynamic account syscalls.
#![cfg(target_os = "solana")]

use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_define_syscall::definitions::{
    sol_account_data_read, sol_account_data_slice, sol_account_data_write,
    sol_account_data_len, sol_account_data_slice_window, sol_account_lamports_get,
    sol_account_lamports_set, sol_cpi_clear_accounts, sol_cpi_load_account,
    sol_cpi_load_accounts, sol_cpi_unload_account,
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

/// Load an account for CPI usage and return its index.
#[inline]
pub fn cpi_load_account_checked(
    pubkey: &Pubkey,
    is_writable: bool,
    is_signer: bool,
) -> Result<u64, ProgramError> {
    let mut index: u64 = 0;
    let ret = unsafe {
        sol_cpi_load_account(
            pubkey.as_ref().as_ptr(),
            is_writable as u64,
            is_signer as u64,
            &mut index as *mut u64,
        )
    };
    if ret == 0 {
        Ok(index)
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Load multiple accounts for CPI usage and return their indexes.
#[inline]
pub fn cpi_load_accounts_checked(
    pubkeys: &[Pubkey],
    is_writable: bool,
    is_signer: bool,
) -> Result<Vec<u64>, ProgramError> {
    let mut indices = vec![0u64; pubkeys.len()];
    let ret = unsafe {
        sol_cpi_load_accounts(
            pubkeys.as_ptr() as *const u8,
            pubkeys.len() as u64,
            is_writable as u64,
            is_signer as u64,
            indices.as_mut_ptr(),
        )
    };
    if ret == 0 {
        Ok(indices)
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Remove a dynamically loaded CPI account from the current instruction.
#[inline]
pub fn cpi_unload_account_checked(pubkey: &Pubkey) -> Result<(), ProgramError> {
    let ret = unsafe { sol_cpi_unload_account(pubkey.as_ref().as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Clear all dynamically loaded CPI accounts from the current instruction.
#[inline]
pub fn cpi_clear_accounts_checked() -> Result<(), ProgramError> {
    let ret = unsafe { sol_cpi_clear_accounts() };
    if ret == 0 {
        Ok(())
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
/// The mapped pointer becomes invalid after any new slice mapping or realloc.
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
/// The mapped pointer becomes invalid after any new slice mapping or realloc.
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

#[inline]
fn account_data_slice_window_impl(
    account_index: u64,
    offset: usize,
    len: usize,
    window_id: u64,
    is_writable: bool,
) -> Result<u64, ProgramError> {
    let mut addr: u64 = 0;
    let flags = (window_id << 1) | u64::from(is_writable);
    let ret = unsafe {
        sol_account_data_slice_window(
            account_index,
            offset as u64,
            len as u64,
            flags,
            &mut addr as *mut u64,
        )
    };
    if ret == 0 {
        Ok(addr)
    } else {
        Err(ProgramError::from(ret))
    }
}

/// Map a window of account data into a selected program memory region (read-only).
/// The mapped pointer becomes invalid after any new slice mapping in the same window or realloc.
#[inline]
pub fn account_data_slice_window(
    account_index: u64,
    offset: usize,
    len: usize,
    window_id: u64,
) -> Result<*const u8, ProgramError> {
    account_data_slice_window_impl(account_index, offset, len, window_id, false)
        .map(|addr| addr as *const u8)
}

/// Map a window of account data into a selected program memory region (writable).
/// The mapped pointer becomes invalid after any new slice mapping in the same window or realloc.
#[inline]
pub fn account_data_slice_mut_window(
    account_index: u64,
    offset: usize,
    len: usize,
    window_id: u64,
) -> Result<*mut u8, ProgramError> {
    account_data_slice_window_impl(account_index, offset, len, window_id, true)
        .map(|addr| addr as *mut u8)
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
