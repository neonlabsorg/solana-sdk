//! Dynamic account syscalls.
#![cfg(target_os = "solana")]

use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_define_syscall::definitions::{
    sol_cpi_load_account, sol_cpi_load_accounts,
};

/// Load an account for CPI usage and return its index.
#[inline]
pub fn cpi_load_account_checked(
    pubkey: &Pubkey,
    is_writable: bool,
    is_signer: bool,
    index: &mut u64,
) -> Result<(), ProgramError> {
    let ret = unsafe {
        sol_cpi_load_account(
            pubkey.as_ref().as_ptr(),
            is_writable as u64,
            is_signer as u64,
            index as *mut u64,
        )
    };
    if ret == 0 {
        Ok(())
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
    indices: &mut [u64],
) -> Result<(), ProgramError> {
    //let mut indices = vec![0u64; pubkeys.len()];
    if indices.len() != pubkeys.len() {
        return Err(ProgramError::InvalidArgument);
    }

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
        Ok(())
    } else {
        Err(ProgramError::from(ret))
    }
}
