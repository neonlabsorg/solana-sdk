//! Dynamic account syscalls.
#![cfg(target_os = "solana")]

use crate::AccountInfo;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_define_syscall::definitions::{
    sol_cpi_load_account, sol_cpi_load_accounts, sol_create_subaccount, sol_set_subaccount_slice,
};

/// Create a new subaccount with the given seeds and space, owned by the caller.
#[inline]
pub fn create_subaccount(
    payer: &Pubkey,
    seeds: &[&[u8]],
    space: u64,
    lamports: u64,
) -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        let result = unsafe {
            sol_create_subaccount(
                payer.as_ref().as_ptr(),
                seeds as *const _ as *const u8,
                seeds.len() as u64,
                space as u64,
                lamports as u64,
            )
        };

        match result {
            0 => Ok(()),
            err => Err(ProgramError::from(err)),
        }
    }
    #[cfg(not(target_os = "solana"))]
    Ok(())
}

#[inline]
pub fn set_subaccount_slice(
    account_infos: &[AccountInfo],
) -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        let result = unsafe {
            sol_set_subaccount_slice(
                account_infos.as_ptr() as *const u8,
                account_infos.len() as u64,
            )
        };

        match result {
            0 => Ok(()),
            err => Err(ProgramError::from(err)),
        }
    }
    #[cfg(not(target_os = "solana"))]
    Ok(())
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
