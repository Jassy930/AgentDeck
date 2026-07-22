// `GlobalKeyStateV1` 的 ADGK1/ADGK2 canonical 编解码。
//
// 本文件由 `pairing_grant.rs` 通过 `include!` 纳入原模块，保持原有私有接口、
// canonical bytes 与错误映射不变。

impl GlobalKeyStateV1 {
    pub(super) fn canonical_bytes(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
        self.validate()?;
        let encoded_len = self.canonical_encoded_len()?;
        if encoded_len > MAX_GLOBAL_KEY_STATE_BYTES {
            return Err(RuntimeStoreError::PairingLimit);
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(encoded_len));
        encoded.extend_from_slice(GLOBAL_KEY_MAGIC_V2);
        encoded.extend_from_slice(&self.revision.to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(self.catalogs.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for catalog in &self.catalogs {
            Self::encode_internal_key(&mut encoded, catalog)?;
        }
        encoded.extend_from_slice(
            &u16::try_from(self.devices.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for device in &self.devices {
            encoded.extend_from_slice(device.device_route.as_bytes());
            encoded.extend_from_slice(&device.revoked_at_ms.unwrap_or(0).to_be_bytes());
            encoded.extend_from_slice(&device.command.epoch.to_be_bytes());
            encoded.extend_from_slice(device.command.encoded_secret());
            encoded.extend_from_slice(&device.reply.epoch.to_be_bytes());
            encoded.extend_from_slice(device.reply.encoded_secret());
        }
        encoded.extend_from_slice(
            &u16::try_from(self.conversations.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for conversation in &self.conversations {
            encoded.extend_from_slice(conversation.stream_route.as_bytes());
            encoded.extend_from_slice(
                &u16::try_from(conversation.history.len())
                    .map_err(|_| RuntimeStoreError::PairingLimit)?
                    .to_be_bytes(),
            );
            for key in &conversation.history {
                Self::encode_internal_key(&mut encoded, key)?;
            }
        }
        encoded.extend_from_slice(
            &u32::try_from(self.retired_key_tombstones.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for target in &self.retired_key_tombstones {
            encoded.extend_from_slice(&target.canonical_bytes());
        }
        debug_assert_eq!(encoded.len(), encoded_len);
        Ok(encoded)
    }

    fn canonical_encoded_len(&self) -> Result<usize, RuntimeStoreError> {
        let overflow = || RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_key_directory_bytes",
        };
        let mut encoded_len = 23_usize;
        for key in &self.catalogs {
            encoded_len = encoded_len
                .checked_add(Self::encoded_internal_key_len(key)?)
                .ok_or_else(overflow)?;
        }
        encoded_len = encoded_len
            .checked_add(self.devices.len().checked_mul(104).ok_or_else(overflow)?)
            .ok_or_else(overflow)?;
        for conversation in &self.conversations {
            encoded_len = encoded_len.checked_add(18).ok_or_else(overflow)?;
            for key in &conversation.history {
                encoded_len = encoded_len
                    .checked_add(Self::encoded_internal_key_len(key)?)
                    .ok_or_else(overflow)?;
            }
        }
        encoded_len = encoded_len
            .checked_add(
                self.retired_key_tombstones
                    .len()
                    .checked_mul(RETIRED_SHARED_KEY_TARGET_BYTES)
                    .ok_or_else(overflow)?,
            )
            .ok_or_else(overflow)?;
        Ok(encoded_len)
    }

    fn ensure_canonical_capacity(&self) -> Result<(), RuntimeStoreError> {
        if self.canonical_encoded_len()? > MAX_GLOBAL_KEY_STATE_BYTES {
            return Err(RuntimeStoreError::PairingLimit);
        }
        Ok(())
    }

    fn encoded_internal_key_len(key: &InternalKey) -> Result<usize, RuntimeStoreError> {
        key.retention_owners
            .len()
            .checked_mul(RETIRED_SHARED_KEY_OWNER_BYTES)
            .and_then(|owner_bytes| INTERNAL_KEY_BASE_BYTES.checked_add(owner_bytes))
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "remote_key_directory_bytes",
            })
    }

    fn encode_internal_key(
        encoded: &mut Vec<u8>,
        key: &InternalKey,
    ) -> Result<(), RuntimeStoreError> {
        encoded.extend_from_slice(&key.epoch.to_be_bytes());
        encoded.extend_from_slice(&key.retired_at_ms.unwrap_or(0).to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(key.retention_owners.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for owner in &key.retention_owners {
            encoded.extend_from_slice(&owner.canonical_bytes());
        }
        encoded.extend_from_slice(key.key.expose_secret());
        Ok(())
    }

    fn from_canonical_bytes(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        if encoded.len() < GLOBAL_KEY_MAGIC_V1.len() || encoded.len() > MAX_GLOBAL_KEY_STATE_BYTES {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        match encoded.get(..5) {
            Some(magic) if magic == GLOBAL_KEY_MAGIC_V1 => Self::from_adgk1_bytes(encoded),
            Some(magic) if magic == GLOBAL_KEY_MAGIC_V2 => Self::from_adgk2_bytes(encoded),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }

    fn from_adgk1_bytes(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        let mut cursor = 0_usize;
        let take = |cursor: &mut usize, count: usize| -> Result<&[u8], RuntimeStoreError> {
            let end = cursor
                .checked_add(count)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            let value = encoded
                .get(*cursor..end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            *cursor = end;
            Ok(value)
        };
        if take(&mut cursor, GLOBAL_KEY_MAGIC_V1.len())? != GLOBAL_KEY_MAGIC_V1 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let revision = u64::from_be_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        let catalog_count = usize::from(u16::from_be_bytes(
            take(&mut cursor, 2)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ));
        if catalog_count == 0 || catalog_count > MAX_DEVICES {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut catalogs = Vec::with_capacity(catalog_count);
        for _ in 0..catalog_count {
            let epoch = u64::from_be_bytes(
                take(&mut cursor, 8)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            catalogs.push(InternalKey::new(
                epoch,
                SecretBytes::new(take(&mut cursor, 32)?.to_vec()),
            )?);
        }
        if catalogs.len() > 1 {
            for catalog in &mut catalogs[..catalog_count - 1] {
                catalog.retire_with_unknown_legacy_time()?;
            }
        }
        let count = usize::from(u16::from_be_bytes(
            take(&mut cursor, 2)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ));
        if count == 0 || count > MAX_DEVICES {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            let device_route = DeviceRouteId::from_bytes(
                take(&mut cursor, 16)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let command_epoch = u64::from_be_bytes(
                take(&mut cursor, 8)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let command_key = SecretBytes::new(take(&mut cursor, 32)?.to_vec());
            let reply_epoch = u64::from_be_bytes(
                take(&mut cursor, 8)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let reply_key = SecretBytes::new(take(&mut cursor, 32)?.to_vec());
            devices.push(DeviceKeys::new(
                device_route,
                command_epoch,
                command_key,
                reply_epoch,
                reply_key,
            )?);
        }
        if cursor != encoded.len() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let value = Self {
            revision,
            catalogs,
            devices,
            conversations: Vec::new(),
            retired_key_tombstones: Vec::new(),
        };
        value.validate()?;
        if value.canonical_adgk1_bytes()?.as_slice() != encoded {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(value)
    }

    fn canonical_adgk1_bytes(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
        self.validate()?;
        if !self.conversations.is_empty()
            || !self.retired_key_tombstones.is_empty()
            || self.devices.iter().any(|device| !device.is_active())
            || self.catalogs.iter().enumerate().any(|(index, key)| {
                if index + 1 == self.catalogs.len() {
                    key.retired_at_ms.is_some()
                } else {
                    key.retired_at_ms != Some(LEGACY_RETIREMENT_TIME_UNKNOWN)
                }
            })
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(
            17 + self.catalogs.len() * 40 + self.devices.len() * 96,
        ));
        encoded.extend_from_slice(GLOBAL_KEY_MAGIC_V1);
        encoded.extend_from_slice(&self.revision.to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(self.catalogs.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for catalog in &self.catalogs {
            encoded.extend_from_slice(&catalog.epoch.to_be_bytes());
            encoded.extend_from_slice(catalog.key.expose_secret());
        }
        encoded.extend_from_slice(
            &u16::try_from(self.devices.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for device in &self.devices {
            encoded.extend_from_slice(device.device_route.as_bytes());
            encoded.extend_from_slice(&device.command.epoch.to_be_bytes());
            encoded.extend_from_slice(device.command.encoded_secret());
            encoded.extend_from_slice(&device.reply.epoch.to_be_bytes());
            encoded.extend_from_slice(device.reply.encoded_secret());
        }
        Ok(encoded)
    }

    fn from_adgk2_bytes(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        let mut cursor = 0_usize;
        let take = |cursor: &mut usize, count: usize| -> Result<&[u8], RuntimeStoreError> {
            let end = cursor
                .checked_add(count)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            let value = encoded
                .get(*cursor..end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            *cursor = end;
            Ok(value)
        };
        if take(&mut cursor, GLOBAL_KEY_MAGIC_V2.len())? != GLOBAL_KEY_MAGIC_V2 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let revision = Self::decode_u64(take(&mut cursor, 8)?)?;
        let catalog_count = usize::from(Self::decode_u16(take(&mut cursor, 2)?)?);
        if catalog_count == 0 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut catalogs = Vec::with_capacity(catalog_count);
        for _ in 0..catalog_count {
            catalogs.push(Self::decode_internal_key(
                &mut cursor,
                &take,
                KeyPurpose::Catalog,
                None,
            )?);
        }
        let device_count = usize::from(Self::decode_u16(take(&mut cursor, 2)?)?);
        if device_count == 0 || device_count > MAX_DEVICE_RECORDS {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut devices = Vec::with_capacity(device_count);
        for _ in 0..device_count {
            let device_route = DeviceRouteId::from_bytes(
                take(&mut cursor, 16)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let revoked_at_ms =
                Self::decode_optional_time(Self::decode_u64(take(&mut cursor, 8)?)?);
            let command_epoch = Self::decode_u64(take(&mut cursor, 8)?)?;
            let command_key = take(&mut cursor, 32)?;
            let reply_epoch = Self::decode_u64(take(&mut cursor, 8)?)?;
            let reply_key = take(&mut cursor, 32)?;
            let command_removed = command_key == REMOVED_DEVICE_TRANSPORT_SECRET;
            let reply_removed = reply_key == REMOVED_DEVICE_TRANSPORT_SECRET;
            let device = match (command_removed, reply_removed, revoked_at_ms) {
                (false, false, revoked_at_ms) => {
                    let mut device = DeviceKeys::new(
                        device_route,
                        command_epoch,
                        SecretBytes::new(command_key.to_vec()),
                        reply_epoch,
                        SecretBytes::new(reply_key.to_vec()),
                    )?;
                    device.revoked_at_ms = revoked_at_ms;
                    device
                }
                (true, true, Some(revoked_at_ms)) => {
                    DeviceKeys::removed(device_route, command_epoch, reply_epoch, revoked_at_ms)?
                }
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            devices.push(device);
        }
        let conversation_count = usize::from(Self::decode_u16(take(&mut cursor, 2)?)?);
        if conversation_count > MAX_ACTIVE_CONVERSATIONS {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut conversations = Vec::with_capacity(conversation_count);
        for _ in 0..conversation_count {
            let stream_route = StreamRouteId::from_bytes(
                take(&mut cursor, 16)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let key_count = usize::from(Self::decode_u16(take(&mut cursor, 2)?)?);
            if key_count == 0 {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let mut history = Vec::with_capacity(key_count);
            for _ in 0..key_count {
                history.push(Self::decode_internal_key(
                    &mut cursor,
                    &take,
                    KeyPurpose::ConversationDek,
                    Some(stream_route),
                )?);
            }
            conversations.push(ConversationKeys {
                stream_route,
                history,
            });
        }
        let tombstone_count = usize::try_from(Self::decode_u32(take(&mut cursor, 4)?)?)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if tombstone_count > MAX_RETIRED_KEY_TOMBSTONES {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut retired_key_tombstones = Vec::with_capacity(tombstone_count);
        for _ in 0..tombstone_count {
            retired_key_tombstones.push(RetiredSharedKeyTarget::from_canonical_bytes(take(
                &mut cursor,
                RETIRED_SHARED_KEY_TARGET_BYTES,
            )?)?);
        }
        if cursor != encoded.len() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let value = Self {
            revision,
            catalogs,
            devices,
            conversations,
            retired_key_tombstones,
        };
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != encoded {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(value)
    }

    fn decode_internal_key<'a>(
        cursor: &mut usize,
        take: &impl Fn(&mut usize, usize) -> Result<&'a [u8], RuntimeStoreError>,
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
    ) -> Result<InternalKey, RuntimeStoreError> {
        let epoch = Self::decode_u64(take(cursor, 8)?)?;
        let retired_at_ms = Self::decode_optional_time(Self::decode_u64(take(cursor, 8)?)?);
        let owner_count = usize::from(Self::decode_u16(take(cursor, 2)?)?);
        if owner_count > MAX_RETENTION_OWNERS_PER_KEY {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut retention_owners = Vec::with_capacity(owner_count);
        for _ in 0..owner_count {
            let owner = RetiredSharedKeyOwner::from_canonical_bytes(take(
                cursor,
                RETIRED_SHARED_KEY_OWNER_BYTES,
            )?)?;
            if !owner.binds_to(purpose, stream_route, epoch) {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            retention_owners.push(owner);
        }
        let mut key = InternalKey::new(epoch, SecretBytes::new(take(cursor, 32)?.to_vec()))?;
        key.retired_at_ms = retired_at_ms;
        key.retention_owners = retention_owners;
        Ok(key)
    }

    fn decode_u64(encoded: &[u8]) -> Result<u64, RuntimeStoreError> {
        encoded
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    fn decode_u16(encoded: &[u8]) -> Result<u16, RuntimeStoreError> {
        encoded
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    fn decode_u32(encoded: &[u8]) -> Result<u32, RuntimeStoreError> {
        encoded
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    const fn decode_optional_time(value: u64) -> Option<u64> {
        if value == 0 { None } else { Some(value) }
    }

    #[cfg(test)]
    pub(crate) fn canonical_bytes_for_test(&self) -> Result<Vec<u8>, RuntimeStoreError> {
        self.canonical_bytes().map(|bytes| bytes.to_vec())
    }

    #[cfg(test)]
    pub(crate) fn from_canonical_bytes_for_test(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        Self::from_canonical_bytes(encoded)
    }
}
