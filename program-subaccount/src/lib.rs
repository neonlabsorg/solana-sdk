//! Account information.
#![cfg_attr(docsrs, feature(doc_cfg))]
use {
    solana_account_info::AccountInfo, solana_address::Address, solana_program_error::ProgramError,
};

#[cfg(target_os = "solana")]
use {
    solana_define_syscall::definitions::{
        sol_create_subaccount, sol_load_subaccount_rust, sol_unload_subaccount,
    },
    solana_program_entrypoint::deserialize_account_info,
};

/// Create a new subaccount with the given seeds and space, owned by the caller.
#[inline]
pub fn create_subaccount(
    payer: &Address,
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
    {
        let _ = (payer, seeds, space, lamports); // avoid unused variable warnings
        Ok(())
    }
}

/// Load subaccount
#[inline]
pub fn load_subaccount<'a>(seeds: &[&[u8]]) -> Result<AccountInfo<'a>, ProgramError> {
    #[cfg(target_os = "solana")]
    {
        let mut account_view_addr = 0u64;
        let mut header_addr = 0u64;

        let result = unsafe {
            sol_load_subaccount_rust(
                seeds as *const _ as *const u8,
                seeds.len() as u64,
                &mut account_view_addr as *mut u64,
                &mut header_addr as *mut u64,
            )
        };

        if result != 0 {
            return Err(ProgramError::from(result));
        }

        let (account_info, _) = unsafe { deserialize_account_info(header_addr as *mut u8, 1) };

        let account: *mut AccountInfo<'a> =
            core::ptr::with_exposed_provenance_mut(account_view_addr as usize);
        unsafe {
            core::ptr::write(account, account_info.clone());
        }

        Ok(account_info)
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = seeds; // avoid unused variable warning
        Err(ProgramError::Custom(0)) // TODO: better error
    }
}

/// Unload subaccount
#[inline]
pub fn unload_subaccount(subaccount: &AccountInfo<'_>) -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        let key_ptr = subaccount.key as *const _ as *const u8;
        let vm_header_addr = unsafe { key_ptr.byte_sub(8) }.expose_provenance() as u64;

        let result = unsafe { sol_unload_subaccount(vm_header_addr) };
        match result {
            0 => Ok(()),
            err => Err(ProgramError::from(err)),
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = subaccount; // avoid unused variable warning
        Ok(())
    }
}
