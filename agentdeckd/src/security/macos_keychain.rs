use super::KeyStoreError;
#[cfg(target_os = "macos")]
use super::{KeyStore, SecretBytes};
use crate::config::compiled_stable_keychain_access_group;

/// macOS Data Protection Keychain generic-password adapter。
///
/// access group 必须由已签名 helper 的真实 provisioning/entitlement 注入；本类型拒绝
/// 缺失、空值和文档占位符，不会回退到登录 Keychain 或明文文件。
#[derive(Debug)]
pub struct MacOsKeychainStore {
    #[cfg(target_os = "macos")]
    service: String,
    #[cfg(target_os = "macos")]
    access_group: String,
}

impl MacOsKeychainStore {
    pub fn new(
        service: impl Into<String>,
        access_group: Option<String>,
    ) -> Result<Self, KeyStoreError> {
        let access_group = access_group.ok_or(KeyStoreError::AccessGroupMissing)?;
        let trimmed = access_group.trim();
        if trimmed.is_empty() {
            return Err(KeyStoreError::AccessGroupMissing);
        }
        const ACCESS_GROUP_SUFFIX: &str = ".com.agentdeck.agentdeckd.stable";
        let valid_prefix = trimmed
            .strip_suffix(ACCESS_GROUP_SUFFIX)
            .is_some_and(|prefix| {
                !prefix.is_empty()
                    && prefix.len() <= 64
                    && prefix.bytes().all(|byte| byte.is_ascii_alphanumeric())
            });
        if trimmed != access_group || !valid_prefix || trimmed.starts_with("TEAMID.") {
            return Err(KeyStoreError::AccessGroupInvalid);
        }
        let compiled =
            compiled_stable_keychain_access_group().ok_or(KeyStoreError::AccessGroupMissing)?;
        if compiled != access_group {
            return Err(KeyStoreError::AccessGroupInvalid);
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = service;
            return Err(KeyStoreError::UnsupportedPlatform);
        }

        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                service: service.into(),
                access_group,
            })
        }
    }

    #[cfg(target_os = "macos")]
    fn options(
        &self,
        account: &str,
        include_access_control: bool,
    ) -> Result<security_framework::passwords::PasswordOptions, KeyStoreError> {
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        use security_framework::passwords::{AccessControlOptions, PasswordOptions};

        let mut options = PasswordOptions::new_generic_password(&self.service, account);
        options.use_protected_keychain();
        options.set_access_synchronized(Some(false));
        options.set_access_group(&self.access_group);
        if include_access_control {
            let access_control = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                AccessControlOptions::empty().bits(),
            )
            .map_err(|error| KeyStoreError::Backend {
                operation: "create_access_control",
                status: error.code(),
            })?;
            options.set_access_control(access_control);
        }
        Ok(options)
    }
}

#[cfg(target_os = "macos")]
impl KeyStore for MacOsKeychainStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        use security_framework::passwords::generic_password;
        use security_framework_sys::base::errSecItemNotFound;

        match generic_password(self.options(account, false)?) {
            Ok(bytes) => Ok(Some(SecretBytes::new(bytes))),
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(error) => Err(KeyStoreError::Backend {
                operation: "load",
                status: error.code(),
            }),
        }
    }

    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
        use security_framework::passwords::set_generic_password_options;

        set_generic_password_options(value.expose_secret(), self.options(account, true)?).map_err(
            |error| KeyStoreError::Backend {
                operation: "store",
                status: error.code(),
            },
        )
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        use security_framework::passwords::delete_generic_password_options;
        use security_framework_sys::base::errSecItemNotFound;

        match delete_generic_password_options(self.options(account, false)?) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Ok(()),
            Err(error) => Err(KeyStoreError::Backend {
                operation: "delete",
                status: error.code(),
            }),
        }
    }
}
