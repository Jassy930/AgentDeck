use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

pub const DAEMON_EXE: &str = if cfg!(windows) {
    "agentdeckd.exe"
} else {
    "agentdeckd"
};

pub fn home_dir() -> Option<PathBuf> {
    home_from(
        std::env::var_os("USERPROFILE").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

fn home_from(profile: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    let profile = profile.filter(|value| !value.is_empty());
    let home = home.filter(|value| !value.is_empty());
    if cfg!(windows) {
        profile.or(home)
    } else {
        home
    }
    .map(PathBuf::from)
}

pub fn data_root(home: Option<&OsStr>, local_app_data: Option<&OsStr>) -> Option<PathBuf> {
    if cfg!(windows) {
        local_app_data
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|home| PathBuf::from(home).join("AppData/Local")))
    } else {
        home.map(|home| {
            PathBuf::from(home).join(if cfg!(target_os = "macos") {
                "Library/Application Support"
            } else {
                ".local/share"
            })
        })
    }
}

/// GUI 的辅助进程保留重定向管道，但不额外弹出 Windows 控制台。
pub fn command(program: impl AsRef<OsStr>) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new(program);
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        command
    }
    #[cfg(not(windows))]
    Command::new(program)
}

/// 命令模式可复用调用者控制台；已有输出管道保持原样，不创建新控制台。
#[cfg(windows)]
pub fn attach_parent_console_if_needed() {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        SetStdHandle,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    // A caller may redirect only stdout. Missing stderr is not a reason to
    // attach a console and replace an already usable machine-readable stream.
    if !stdout.is_null() && stdout != INVALID_HANDLE_VALUE {
        return;
    }

    let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    let preserved_stderr = if !stderr.is_null() && stderr != INVALID_HANDLE_VALUE {
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                process,
                stderr,
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            // If preservation fails, leave the caller's existing stream alone.
            return;
        }
        Some(unsafe { OwnedHandle::from_raw_handle(duplicate) })
    } else {
        None
    };
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } != 0 {
        if let Some(stderr) = preserved_stderr {
            if unsafe { SetStdHandle(STD_ERROR_HANDLE, stderr.as_raw_handle()) } != 0 {
                // Standard handles are process-owned. The duplicate must stay
                // open after this function; restoring a saved raw value alone
                // would not protect its lifetime across console attachment.
                let _ = stderr.into_raw_handle();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_and_data_roots_follow_the_host_platform() {
        let home = OsStr::new("home");
        let profile = OsStr::new("profile");
        assert_eq!(
            home_from(Some(profile), Some(home)),
            Some(PathBuf::from(if cfg!(windows) { profile } else { home }))
        );
        assert_eq!(home_from(None, Some(home)), Some(PathBuf::from(home)));
        assert!(home_from(None, Some(OsStr::new(""))).is_none());
        let expected = if cfg!(windows) {
            "AppData/Local"
        } else if cfg!(target_os = "macos") {
            "Library/Application Support"
        } else {
            ".local/share"
        };
        assert_eq!(
            data_root(Some(home), None),
            Some(PathBuf::from(home).join(expected))
        );
        if cfg!(windows) {
            assert_eq!(
                data_root(None, Some(OsStr::new("local-data"))),
                Some(PathBuf::from("local-data"))
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn command_mode_preserves_inherited_output_handles() {
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        };
        let handles = unsafe {
            [
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetStdHandle(STD_ERROR_HANDLE),
            ]
        };
        assert!(handles.iter().all(|handle| !handle.is_null()));
        attach_parent_console_if_needed();
        assert_eq!(handles, unsafe {
            [
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetStdHandle(STD_ERROR_HANDLE),
            ]
        });
    }
}
