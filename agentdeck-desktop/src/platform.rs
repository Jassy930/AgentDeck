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
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        SetStdHandle,
    };
    let streams = [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].map(|stream| {
        let handle = unsafe { GetStdHandle(stream) };
        (
            stream,
            handle,
            !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        )
    });
    if streams.iter().all(|(_, _, valid)| *valid) {
        return;
    }
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } != 0 {
        for (stream, handle, valid) in streams {
            if valid {
                unsafe { SetStdHandle(stream, handle) };
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
