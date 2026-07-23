//! macOS persistent remote CLI 的 Data Protection Keychain adapter。
//!
//! 本层只接受已经完成当前二进制签名、TeamIdentifier 与 CLI-only access-group
//! 读回的 [`VerifiedRemoteCliIdentity`]。所有查询都固定到同一 service/access group、
//! non-sync、ThisDeviceOnly 与 non-interactive policy；不存在登录 Keychain 或文件降级。

#![cfg(target_os = "macos")]

use std::ffi::{CStr, c_void};
use std::fmt;
use std::ptr;
use std::slice;
use std::sync::Arc;

use core_foundation_sys::array::{
    CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFArrayRef,
};
use core_foundation_sys::base::{CFGetTypeID, CFIndex, CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::data::{
    CFDataCreate, CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID, CFDataRef,
};
use core_foundation_sys::dictionary::{
    CFDictionaryCreate, CFDictionaryGetTypeID, CFDictionaryGetValue, CFDictionaryRef,
    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
};
use core_foundation_sys::number::{
    CFNumberCreate, kCFBooleanFalse, kCFBooleanTrue, kCFNumberCFIndexType,
};
use core_foundation_sys::string::{
    CFStringCreateWithBytes, CFStringGetCString, CFStringGetTypeID, CFStringRef,
    kCFStringEncodingUTF8,
};

use super::keychain::{
    MAX_ENUMERATED_REMOTE_KEYCHAIN_ACCOUNT_ATTRIBUTES, MAX_REMOTE_KEY_ACCOUNT_BYTES,
    ParsedPairedRemoteKeyAccount, REMOTE_KEYCHAIN_SERVICE, RemoteKeyAccount, RemoteKeyPersistence,
    RemoteKeyStore, RemoteKeyStoreError, RemoteSecret, validate_enumerated_accounts,
};
use super::signature::VerifiedRemoteCliIdentity;

const ERR_SEC_SUCCESS: OSStatus = 0;
const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25_299;
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25_300;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: CFStringRef;
    static kSecClassGenericPassword: CFStringRef;
    static kSecAttrService: CFStringRef;
    static kSecAttrAccount: CFStringRef;
    static kSecAttrAccessGroup: CFStringRef;
    static kSecAttrSynchronizable: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
    static kSecUseDataProtectionKeychain: CFStringRef;
    static kSecUseAuthenticationUI: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
    static kSecUseAuthenticationUISkip: CFStringRef;
    static kSecValueData: CFStringRef;
    static kSecReturnData: CFStringRef;
    static kSecReturnAttributes: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;

    fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemUpdate(query: CFDictionaryRef, attributes_to_update: CFDictionaryRef) -> OSStatus;
    fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
}

/// 所有 add/load/update/delete 共用的不可变 production policy。
#[derive(Clone, Copy)]
pub(crate) struct RemoteKeychainPolicy<'a> {
    access_group: &'a str,
}

impl<'a> RemoteKeychainPolicy<'a> {
    const fn new(access_group: &'a str) -> Self {
        Self { access_group }
    }

    #[must_use]
    pub(crate) const fn service(&self) -> &'static str {
        REMOTE_KEYCHAIN_SERVICE
    }

    #[must_use]
    pub(crate) const fn access_group(&self) -> &'a str {
        self.access_group
    }

    #[must_use]
    pub(crate) const fn uses_data_protection_keychain(&self) -> bool {
        true
    }

    #[must_use]
    pub(crate) const fn synchronizable(&self) -> bool {
        false
    }

    #[must_use]
    pub(crate) const fn accessibility_name(&self) -> &'static str {
        "after-first-unlock-this-device-only"
    }

    #[must_use]
    pub(crate) const fn authentication_ui_name(
        &self,
        operation: RemoteKeychainOperation,
    ) -> &'static str {
        match operation {
            RemoteKeychainOperation::CopyMatching => "skip",
            RemoteKeychainOperation::ListAccountAttributes => "skip",
            RemoteKeychainOperation::Add
            | RemoteKeychainOperation::Update
            | RemoteKeychainOperation::Delete => "fail",
        }
    }
}

impl fmt::Debug for RemoteKeychainPolicy<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteKeychainPolicy")
            .field("service", &REMOTE_KEYCHAIN_SERVICE)
            .field("access_group", &"[VERIFIED]")
            .field("data_protection", &true)
            .field("synchronizable", &false)
            .field("accessible", &self.accessibility_name())
            .field(
                "copy_authentication_ui",
                &self.authentication_ui_name(RemoteKeychainOperation::CopyMatching),
            )
            .field(
                "mutation_authentication_ui",
                &self.authentication_ui_name(RemoteKeychainOperation::Add),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddOutcome {
    Inserted,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteOutcome {
    Deleted,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpdateOutcome {
    Updated,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteKeychainOperation {
    Add,
    CopyMatching,
    ListAccountAttributes,
    Update,
    Delete,
}

/// Security.framework seam。production composition 固定使用 `SystemSecurityItems`；
/// trait 只让 automatic test 验证相同 add/readback/update/delete 状态机与 policy。
pub(crate) trait SecurityItemBackend: Send + Sync {
    fn add(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
        value: &[u8],
    ) -> Result<AddOutcome, ()>;

    fn load(&self, policy: &RemoteKeychainPolicy<'_>, account: &str)
    -> Result<Option<Vec<u8>>, ()>;

    /// 只返回 generic-password item 的 account attribute；不得请求或返回 value data。
    fn list_account_attributes(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        limit: usize,
    ) -> Result<Vec<String>, ()>;

    /// 用 `SecItemUpdate` 更新 existing item；expected-bytes preflight 位于 store 状态机。
    fn update_existing(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
        replacement: &[u8],
    ) -> Result<UpdateOutcome, ()>;

    fn delete(&self, policy: &RemoteKeychainPolicy<'_>, account: &str)
    -> Result<DeleteOutcome, ()>;
}

struct SystemSecurityItems;

impl SecurityItemBackend for SystemSecurityItems {
    fn add(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
        value: &[u8],
    ) -> Result<AddOutcome, ()> {
        let query = SecurityItemQuery::new(
            policy,
            Some(account),
            Some(value),
            RemoteKeychainOperation::Add,
            None,
        )?;
        // SAFETY: query owns a live immutable CFDictionary for the duration of the call;
        // a null result pointer requests no returned object.
        match unsafe { SecItemAdd(query.as_ref(), ptr::null_mut()) } {
            ERR_SEC_SUCCESS => Ok(AddOutcome::Inserted),
            ERR_SEC_DUPLICATE_ITEM => Ok(AddOutcome::Duplicate),
            _ => Err(()),
        }
    }

    fn load(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
    ) -> Result<Option<Vec<u8>>, ()> {
        let query = SecurityItemQuery::new(
            policy,
            Some(account),
            None,
            RemoteKeychainOperation::CopyMatching,
            None,
        )?;
        let mut result: CFTypeRef = ptr::null();
        // SAFETY: query owns a live immutable CFDictionary and `result` is a valid out pointer.
        let status = unsafe { SecItemCopyMatching(query.as_ref(), &mut result) };
        match status {
            ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            ERR_SEC_SUCCESS => {
                let result = OwnedCf::new(result).ok_or(())?;
                // SAFETY: successful SecItemCopyMatching returned an owned CF object.
                if unsafe { CFGetTypeID(result.as_ref()) } != unsafe { CFDataGetTypeID() } {
                    return Err(());
                }
                let data = result
                    .as_ref()
                    .cast::<core_foundation_sys::data::__CFData>();
                // SAFETY: the type-id check above proves that `data` is CFData and it remains
                // retained by `result` while its bytes are copied.
                let length = unsafe { CFDataGetLength(data) };
                let length = usize::try_from(length).map_err(|_| ())?;
                // SAFETY: `data` is a live CFData. A null pointer is only accepted for length 0.
                let bytes = unsafe { CFDataGetBytePtr(data) };
                if length != 0 && bytes.is_null() {
                    return Err(());
                }
                let value = if length == 0 {
                    Vec::new()
                } else {
                    // SAFETY: CFData promises `length` readable bytes for its live byte pointer.
                    unsafe { slice::from_raw_parts(bytes, length) }.to_vec()
                };
                Ok(Some(value))
            }
            _ => Err(()),
        }
    }

    fn list_account_attributes(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        limit: usize,
    ) -> Result<Vec<String>, ()> {
        let query = SecurityItemQuery::new(
            policy,
            None,
            None,
            RemoteKeychainOperation::ListAccountAttributes,
            Some(limit),
        )?;
        let mut result: CFTypeRef = ptr::null();
        // SAFETY: query owns a live immutable CFDictionary and `result` is a valid out pointer.
        let status = unsafe { SecItemCopyMatching(query.as_ref(), &mut result) };
        match status {
            ERR_SEC_ITEM_NOT_FOUND => Ok(Vec::new()),
            ERR_SEC_SUCCESS => {
                let result = OwnedCf::new(result).ok_or(())?;
                // SAFETY: successful SecItemCopyMatching returned an owned CF object.
                if unsafe { CFGetTypeID(result.as_ref()) } != unsafe { CFArrayGetTypeID() } {
                    return Err(());
                }
                let array: CFArrayRef = result
                    .as_ref()
                    .cast::<core_foundation_sys::array::__CFArray>();
                // SAFETY: the type-id check above proves `array` is CFArray and `result` retains it.
                let count = unsafe { CFArrayGetCount(array) };
                let count = usize::try_from(count).map_err(|_| ())?;
                if count > limit {
                    return Err(());
                }
                let mut accounts = Vec::with_capacity(count);
                for index in 0..count {
                    let index = CFIndex::try_from(index).map_err(|_| ())?;
                    // SAFETY: `index < count` and the live array retains each returned value.
                    let attributes = unsafe { CFArrayGetValueAtIndex(array, index) };
                    if attributes.is_null()
                        || unsafe { CFGetTypeID(attributes) } != unsafe { CFDictionaryGetTypeID() }
                    {
                        return Err(());
                    }
                    let attributes: CFDictionaryRef =
                        attributes.cast::<core_foundation_sys::dictionary::__CFDictionary>();
                    // SAFETY: attributes is a live CFDictionary and kSecAttrAccount is a
                    // process-lifetime key. The returned value is retained by the dictionary.
                    let account =
                        unsafe { CFDictionaryGetValue(attributes, kSecAttrAccount.cast()) };
                    if account.is_null()
                        || unsafe { CFGetTypeID(account) } != unsafe { CFStringGetTypeID() }
                    {
                        return Err(());
                    }
                    accounts.push(copy_bounded_account_string(account.cast())?);
                }
                Ok(accounts)
            }
            _ => Err(()),
        }
    }

    fn update_existing(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
        replacement: &[u8],
    ) -> Result<UpdateOutcome, ()> {
        let query = SecurityItemQuery::new(
            policy,
            Some(account),
            None,
            RemoteKeychainOperation::Update,
            None,
        )?;
        let attributes = SecurityItemUpdateAttributes::new(replacement)?;
        // SAFETY: both wrappers own live immutable CFDictionaries for the duration of the call.
        match unsafe { SecItemUpdate(query.as_ref(), attributes.as_ref()) } {
            ERR_SEC_SUCCESS => Ok(UpdateOutcome::Updated),
            ERR_SEC_ITEM_NOT_FOUND => Ok(UpdateOutcome::NotFound),
            _ => Err(()),
        }
    }

    fn delete(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
    ) -> Result<DeleteOutcome, ()> {
        let query = SecurityItemQuery::new(
            policy,
            Some(account),
            None,
            RemoteKeychainOperation::Delete,
            None,
        )?;
        // SAFETY: query owns a live immutable CFDictionary for the duration of the call.
        match unsafe { SecItemDelete(query.as_ref()) } {
            ERR_SEC_SUCCESS => Ok(DeleteOutcome::Deleted),
            ERR_SEC_ITEM_NOT_FOUND => Ok(DeleteOutcome::NotFound),
            _ => Err(()),
        }
    }
}

/// 发行签名 CLI 的唯一 persistent remote keystore。
///
/// ```compile_fail
/// use agentdeck_cli::remote::macos_keychain::MacOsRemoteKeyStore;
/// let _ = MacOsRemoteKeyStore::new("raw-access-group");
/// ```
pub struct MacOsRemoteKeyStore {
    access_group: String,
    backend: Arc<dyn SecurityItemBackend>,
}

impl MacOsRemoteKeyStore {
    #[must_use]
    pub fn new(identity: &VerifiedRemoteCliIdentity) -> Self {
        Self {
            access_group: identity.keychain_access_group().to_owned(),
            backend: Arc::new(SystemSecurityItems),
        }
    }

    /// 只在 automatic policy test 编译；仍要求 verified identity，不能从 raw group
    /// 构造，也不会形成 production CLI/env/config 选择面。
    #[cfg(test)]
    pub(crate) fn new_with_backend(
        identity: &VerifiedRemoteCliIdentity,
        backend: Arc<dyn SecurityItemBackend>,
    ) -> Self {
        Self {
            access_group: identity.keychain_access_group().to_owned(),
            backend,
        }
    }

    fn policy(&self) -> RemoteKeychainPolicy<'_> {
        RemoteKeychainPolicy::new(&self.access_group)
    }

    fn backend_error() -> RemoteKeyStoreError {
        // 现有 shared error contract 只暴露稳定 unavailable code，不泄漏 OSStatus。
        RemoteKeyStoreError::BackendUnavailable
    }
}

impl fmt::Debug for MacOsRemoteKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacOsRemoteKeyStore([VERIFIED CLI ACCESS GROUP])")
    }
}

impl RemoteKeyStore for MacOsRemoteKeyStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        self.backend
            .load(&self.policy(), account.as_str())
            .map(|value| value.map(RemoteSecret::new))
            .map_err(|()| Self::backend_error())
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        let outcome = self
            .backend
            .add(&self.policy(), account.as_str(), value.expose_secret())
            .map_err(|()| Self::backend_error())?;
        let durable = self.load(account)?;
        match (outcome, durable) {
            (AddOutcome::Inserted, Some(durable))
                if durable.expose_secret() == value.expose_secret() =>
            {
                Ok(RemoteKeyPersistence::Inserted)
            }
            (AddOutcome::Duplicate, Some(durable))
                if durable.expose_secret() == value.expose_secret() =>
            {
                Ok(RemoteKeyPersistence::AlreadyPresent)
            }
            (AddOutcome::Duplicate, Some(_)) => Err(RemoteKeyStoreError::ImmutableConflict {
                account: account.clone(),
            }),
            (AddOutcome::Inserted | AddOutcome::Duplicate, None)
            | (AddOutcome::Inserted, Some(_)) => {
                Err(RemoteKeyStoreError::PersistenceReadbackFailed {
                    account: account.clone(),
                })
            }
        }
    }

    fn compare_and_replace_exact(
        &self,
        account: &RemoteKeyAccount,
        expected: &RemoteSecret,
        replacement: &RemoteSecret,
    ) -> Result<(), RemoteKeyStoreError> {
        let policy = self.policy();
        let current = self
            .backend
            .load(&policy, account.as_str())
            .map_err(|()| Self::backend_error())?
            .map(RemoteSecret::new);
        let Some(current) = current else {
            return Err(RemoteKeyStoreError::CompareAndReplaceMissing {
                account: account.clone(),
            });
        };
        if current.expose_secret() != expected.expose_secret() {
            return Err(RemoteKeyStoreError::CompareAndReplaceMismatch {
                account: account.clone(),
            });
        }

        // SecItem.h 只允许 Attribute/Search Constants 参与 SecItemUpdate query；
        // kSecValueData 是 Value Type Key，不能合法用于 old-bytes search。当前威胁边界据此采用
        // single-writer exact preflight + existing-only update；同 UID 在线 check/update 竞态是
        // 明确的 residual risk，不在本存储原语的安全承诺内。
        let outcome = self
            .backend
            .update_existing(&policy, account.as_str(), replacement.expose_secret())
            .map_err(|()| RemoteKeyStoreError::CompareAndReplaceCommitUnknown {
                account: account.clone(),
            })?;
        if outcome != UpdateOutcome::Updated {
            return Err(RemoteKeyStoreError::CompareAndReplaceCommitUnknown {
                account: account.clone(),
            });
        }

        let durable = self
            .backend
            .load(&policy, account.as_str())
            .map_err(|()| RemoteKeyStoreError::CompareAndReplaceCommitUnknown {
                account: account.clone(),
            })?
            .map(RemoteSecret::new);
        if durable.as_ref().map(RemoteSecret::expose_secret) != Some(replacement.expose_secret()) {
            return Err(RemoteKeyStoreError::CompareAndReplaceCommitUnknown {
                account: account.clone(),
            });
        }
        Ok(())
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        let _ = self
            .backend
            .delete(&self.policy(), account.as_str())
            .map_err(|()| Self::backend_error())?;
        if self.load(account)?.is_some() {
            return Err(RemoteKeyStoreError::DeleteReadbackFailed {
                account: account.clone(),
            });
        }
        Ok(())
    }

    fn list_paired_commit_markers(
        &self,
        installation_id: uuid::Uuid,
    ) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
        let accounts = self
            .backend
            .list_account_attributes(
                &self.policy(),
                MAX_ENUMERATED_REMOTE_KEYCHAIN_ACCOUNT_ATTRIBUTES + 1,
            )
            .map_err(|()| Self::backend_error())?;
        validate_enumerated_accounts(accounts, installation_id)
    }
}

fn copy_bounded_account_string(value: CFStringRef) -> Result<String, ()> {
    let mut buffer = [0_i8; MAX_REMOTE_KEY_ACCOUNT_BYTES + 1];
    let buffer_size = CFIndex::try_from(buffer.len()).map_err(|_| ())?;
    // SAFETY: `value` has been type-checked as a live CFString; `buffer` is writable for
    // `buffer_size` bytes and CoreFoundation always NUL-terminates a successful conversion.
    if unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer_size,
            kCFStringEncodingUTF8,
        )
    } == 0
    {
        return Err(());
    }
    // SAFETY: successful CFStringGetCString wrote a NUL-terminated string within `buffer`.
    let account = unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_str()
        .map_err(|_| ())?;
    Ok(account.to_owned())
}

struct OwnedCf(CFTypeRef);

impl OwnedCf {
    fn new(value: CFTypeRef) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }

    const fn as_ref(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: `OwnedCf` is only constructed from create/copy-rule non-null CF objects and
        // owns exactly one retain.
        unsafe { CFRelease(self.0) };
    }
}

struct SecurityItemQuery {
    dictionary: CFDictionaryRef,
    _owned_values: Vec<OwnedCf>,
}

struct SecurityItemUpdateAttributes(SecurityItemQuery);

impl SecurityItemUpdateAttributes {
    fn new(replacement: &[u8]) -> Result<Self, ()> {
        let mut builder = QueryBuilder::default();
        // SAFETY: kSecValueData is an immutable process-lifetime CoreFoundation key; builder
        // owns the copied CFData through the SecItemUpdate call.
        unsafe { builder.owned_data(kSecValueData, replacement)? };
        Ok(Self(builder.build()?))
    }

    const fn as_ref(&self) -> CFDictionaryRef {
        self.0.as_ref()
    }
}

impl SecurityItemQuery {
    fn new(
        policy: &RemoteKeychainPolicy<'_>,
        account: Option<&str>,
        value: Option<&[u8]>,
        operation: RemoteKeychainOperation,
        enumeration_limit: Option<usize>,
    ) -> Result<Self, ()> {
        match operation {
            RemoteKeychainOperation::ListAccountAttributes
                if account.is_none() && value.is_none() && enumeration_limit.is_some() => {}
            RemoteKeychainOperation::Add
                if account.is_some() && value.is_some() && enumeration_limit.is_none() => {}
            RemoteKeychainOperation::CopyMatching
            | RemoteKeychainOperation::Update
            | RemoteKeychainOperation::Delete
                if account.is_some() && value.is_none() && enumeration_limit.is_none() => {}
            _ => return Err(()),
        }
        let mut builder = QueryBuilder::default();
        // SAFETY: all kSec/kCF symbols are immutable process-lifetime CoreFoundation objects.
        unsafe {
            let data_protection = if policy.uses_data_protection_keychain() {
                kCFBooleanTrue
            } else {
                kCFBooleanFalse
            };
            let synchronizable = if policy.synchronizable() {
                kCFBooleanTrue
            } else {
                kCFBooleanFalse
            };
            builder.borrowed(kSecClass, kSecClassGenericPassword);
            builder.owned_string(kSecAttrService, policy.service())?;
            if let Some(account) = account {
                builder.owned_string(kSecAttrAccount, account)?;
            }
            builder.owned_string(kSecAttrAccessGroup, policy.access_group())?;
            builder.borrowed(kSecUseDataProtectionKeychain, data_protection);
            builder.borrowed(kSecAttrSynchronizable, synchronizable);
            builder.borrowed(
                kSecAttrAccessible,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            );
            let authentication_ui = match operation {
                RemoteKeychainOperation::CopyMatching => kSecUseAuthenticationUISkip,
                RemoteKeychainOperation::ListAccountAttributes => kSecUseAuthenticationUISkip,
                RemoteKeychainOperation::Add
                | RemoteKeychainOperation::Update
                | RemoteKeychainOperation::Delete => kSecUseAuthenticationUIFail,
            };
            builder.borrowed(kSecUseAuthenticationUI, authentication_ui);
            if let Some(value) = value {
                builder.owned_data(kSecValueData, value)?;
            }
            if operation == RemoteKeychainOperation::CopyMatching {
                builder.borrowed(kSecReturnData, kCFBooleanTrue.cast::<c_void>());
                builder.borrowed(kSecMatchLimit, kSecMatchLimitOne);
            }
            if operation == RemoteKeychainOperation::ListAccountAttributes {
                builder.borrowed(kSecReturnAttributes, kCFBooleanTrue.cast::<c_void>());
                builder.owned_cf_index(kSecMatchLimit, enumeration_limit.ok_or(())?)?;
            }
        }
        builder.build()
    }

    const fn as_ref(&self) -> CFDictionaryRef {
        self.dictionary
    }
}

impl Drop for SecurityItemQuery {
    fn drop(&mut self) {
        // SAFETY: `dictionary` is a non-null create-rule CFDictionary owned by this value.
        unsafe { CFRelease(self.dictionary.cast()) };
    }
}

#[derive(Default)]
struct QueryBuilder {
    keys: Vec<*const c_void>,
    values: Vec<*const c_void>,
    owned_values: Vec<OwnedCf>,
}

impl QueryBuilder {
    unsafe fn borrowed<T, U>(&mut self, key: *const T, value: *const U) {
        self.keys.push(key.cast());
        self.values.push(value.cast());
    }

    unsafe fn owned_string(&mut self, key: CFStringRef, value: &str) -> Result<(), ()> {
        let length = CFIndex::try_from(value.len()).map_err(|_| ())?;
        // SAFETY: UTF-8 bytes remain live for the call and CoreFoundation copies them.
        let string = unsafe {
            CFStringCreateWithBytes(
                ptr::null(),
                value.as_ptr(),
                length,
                kCFStringEncodingUTF8,
                0,
            )
        };
        let owned = OwnedCf::new(string.cast()).ok_or(())?;
        // SAFETY: the created CFString remains retained by `owned_values` through dictionary use.
        unsafe { self.owned(key, owned) };
        Ok(())
    }

    unsafe fn owned_data(&mut self, key: CFStringRef, value: &[u8]) -> Result<(), ()> {
        let length = CFIndex::try_from(value.len()).map_err(|_| ())?;
        let bytes = if value.is_empty() {
            ptr::null()
        } else {
            value.as_ptr()
        };
        // SAFETY: input bytes remain live for the call and CoreFoundation copies them.
        let data: CFDataRef = unsafe { CFDataCreate(ptr::null(), bytes, length) };
        let owned = OwnedCf::new(data.cast()).ok_or(())?;
        // SAFETY: the created CFData remains retained by `owned_values` through dictionary use.
        unsafe { self.owned(key, owned) };
        Ok(())
    }

    unsafe fn owned_cf_index(&mut self, key: CFStringRef, value: usize) -> Result<(), ()> {
        let value = CFIndex::try_from(value).map_err(|_| ())?;
        // SAFETY: `value` remains live for the call and CoreFoundation copies it into CFNumber.
        let number =
            unsafe { CFNumberCreate(ptr::null(), kCFNumberCFIndexType, (&raw const value).cast()) };
        let owned = OwnedCf::new(number.cast()).ok_or(())?;
        // SAFETY: the created CFNumber remains retained by `owned_values` through dictionary use.
        unsafe { self.owned(key, owned) };
        Ok(())
    }

    unsafe fn owned(&mut self, key: CFStringRef, value: OwnedCf) {
        self.keys.push(key.cast());
        self.values.push(value.as_ref());
        self.owned_values.push(value);
    }

    fn build(self) -> Result<SecurityItemQuery, ()> {
        if self.keys.len() != self.values.len() {
            return Err(());
        }
        let count = CFIndex::try_from(self.keys.len()).map_err(|_| ())?;
        // SAFETY: key/value arrays contain live CF objects; CF type callbacks retain all entries.
        let dictionary = unsafe {
            CFDictionaryCreate(
                ptr::null(),
                self.keys.as_ptr(),
                self.values.as_ptr(),
                count,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            )
        };
        if dictionary.is_null() {
            return Err(());
        }
        Ok(SecurityItemQuery {
            dictionary,
            _owned_values: self.owned_values,
        })
    }
}
