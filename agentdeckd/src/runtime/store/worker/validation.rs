use super::RuntimeStoreError;

pub(super) fn memory_charge(
    base_bytes: usize,
    allocations: &[usize],
) -> Result<u32, RuntimeStoreError> {
    let total = allocations
        .iter()
        .try_fold(base_bytes, |total, allocation| {
            total
                .checked_add(*allocation)
                .ok_or(RuntimeStoreError::PayloadTooLarge)
        })?;
    u32::try_from(total).map_err(|_| RuntimeStoreError::PayloadTooLarge)
}

pub(super) fn validate_maximum(actual: usize, maximum: usize) -> Result<(), RuntimeStoreError> {
    if actual > maximum {
        Err(RuntimeStoreError::PayloadTooLarge)
    } else {
        Ok(())
    }
}

pub(super) fn validate_nonempty_maximum(
    value: &[u8],
    maximum: usize,
) -> Result<(), RuntimeStoreError> {
    if value.is_empty() {
        Err(RuntimeStoreError::InvalidConfig(
            "execution nonce must not be empty",
        ))
    } else {
        validate_maximum(value.len(), maximum)
    }
}
