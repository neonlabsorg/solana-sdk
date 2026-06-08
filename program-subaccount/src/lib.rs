//! Account information.
#![cfg_attr(docsrs, feature(doc_cfg))]
use {
    solana_account_info::AccountInfo, solana_address::Address, solana_program_error::ProgramError,
};

/// Bytes reserved at the start of each subaccount slot for the program's
/// account-view buffer, into which [`load_subaccount`] writes an `AccountInfo`.
///
/// Sized to fit the larger of the two view layouts a program may write here —
/// the C-ABI `SolAccountInfo` (56 bytes, 6× u64 + 3× bool padded to 8) or the
/// Rust SDK `AccountInfo<'_>` (48 bytes, 5× pointer-sized + 3× bool padded to
/// 8). 56 is u64-aligned, so the subsequent slot header keeps its 8-byte field
/// alignment.
///
/// This is the canonical definition shared with the runtime
/// (`solana-program-runtime` re-exports it for its serialization layer).
pub const SUBACCOUNT_ACCOUNT_VIEW_RESERVED_SIZE: usize = 56;

/// The runtime reserves exactly [`SUBACCOUNT_ACCOUNT_VIEW_RESERVED_SIZE`] bytes
/// for the account-view buffer, so the `AccountInfo` written there by
/// [`load_subaccount`] must fit within that reservation.
const _: () = assert!(
    core::mem::size_of::<AccountInfo>() <= SUBACCOUNT_ACCOUNT_VIEW_RESERVED_SIZE,
    "AccountInfo does not fit within the reserved subaccount account-view buffer",
);

#[cfg(target_os = "solana")]
use {
    solana_define_syscall::definitions::{
        sol_create_subaccount, sol_load_subaccount_rust, sol_read_subaccount,
        sol_unload_subaccount,
    },
    solana_program_entrypoint::deserialize_account_info,
};

/// Create a new subaccount with the given seeds and space, owned by the caller.
/// 
/// Requirements:
///  - the first seed must be the base key for the subaccount, present in the account list and writable;
///  - if lamports is not zero, the payer must be a writable signer in outer instruction;
///  - space ≤ MAX_PERMITTED_DATA_LENGTH;
///  - seed/seeds-len limits inherited from MAX_SEEDS/MAX_SEED_LEN.
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
                space,
                lamports,
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
        unimplemented!("create_subaccount is only supported on Solana");
    }
}

/// Load subaccount for the given seeds and return an `AccountInfo` view into it.
/// 
/// Subaccount inherits the same writable permission as a base account, which must be
/// the first seed and must be present in the account list. The returned `AccountInfo`
/// is valid until the subaccount is unloaded or the program invocation ends, and must 
/// not be used after either of those events.
/// There is not available to load subaccounts with the same seeds more than once concurrently
/// (i.e., without unloading in between), and doing so will result in an error
/// InstructionError::AccountAlreadyInitialized.
///
/// Requirements:
///  - the first seed must be the base key for the subaccount, present in the account list.
///
/// # Safety
///
/// The returned `AccountInfo<'a>` is constructed from raw runtime-managed memory.
/// Callers must ensure that the chosen lifetime `'a` does not outlive the loaded
/// subaccount backing storage, that the account is not used after it is unloaded,
/// and that all references derived from the returned value remain confined to the
/// current valid invocation/loading scope.
#[inline]
pub unsafe fn load_subaccount<'a>(seeds: &[&[u8]]) -> Result<AccountInfo<'a>, ProgramError> {
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
        unimplemented!("load_subaccount is only supported on Solana");
    }
}

/// Read raw bytes from a subaccount's data without loading it into a slot.
///
/// Copies exactly `buf.len()` bytes starting at `offset` from the subaccount
/// derived from `seeds` into `buf`. Unlike [`load_subaccount`], this does not
/// occupy a slot and returns no `AccountInfo` view — it is a one-shot copy out
/// of the subaccount's data.
///
/// The requested range `[offset, offset + buf.len())` must lie entirely within
/// the subaccount's data; otherwise the syscall fails with
/// `ProgramError::InvalidArgument`. A subaccount that does not exist has empty
/// data, so any positive-length read of a missing subaccount fails the same
/// way.
///
/// Requirements:
///  - the first seed must be the base key for the subaccount, present in the
///    account list.
#[inline]
pub fn read_subaccount(seeds: &[&[u8]], buf: &mut [u8], offset: u64) -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        let result = unsafe {
            sol_read_subaccount(
                seeds as *const _ as *const u8,
                seeds.len() as u64,
                buf.as_mut_ptr(),
                offset,
                buf.len() as u64,
            )
        };

        match result {
            0 => Ok(()),
            err => Err(ProgramError::from(err)),
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = (seeds, buf, offset); // avoid unused variable warnings
        unimplemented!("read_subaccount is only supported on Solana");
    }
}

/// Unload subaccount.
///
/// Unloading a subaccount invalidates the `AccountInfo` returned by `load_subaccount`,
/// and any clones or borrows of it. Unloading a subaccount that is not currently loaded, 
/// or that has already been unloaded, will result in an error InstructionError::InvalidArgument.
///
/// # Safety
///
/// Unloading a subaccount can invalidate the memory referenced by `subaccount`
/// and by any `AccountInfo` clones or outstanding borrows that alias the same
/// underlying subaccount state. The caller must ensure that no such aliases or
/// borrows are used after this function returns, and that unloading this
/// subaccount is otherwise valid in the current runtime context.
#[inline]
pub unsafe fn unload_subaccount(subaccount: &AccountInfo<'_>) -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        // We assume that the `AccountInfo` was constructed from a valid `sol_load_subaccount` call,
        // and that the subaccount key is located at a fixed offset from the `sol_load_subaccount`-returned 
        // header pointer.
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
        unimplemented!("unload_subaccount is only supported on Solana");
    }
}
