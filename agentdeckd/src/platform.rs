//! Platform paths and native executable discovery; vendor policy stays in adapters.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

pub(crate) fn home_dir() -> Option<PathBuf> {
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

pub(crate) fn native_executable(path: &Path) -> bool {
    !cfg!(windows)
        || path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

pub(crate) fn executable_candidates(name: &str) -> Vec<PathBuf> {
    executable_candidates_from(
        name,
        std::env::var_os("PATH").as_deref(),
        home_dir().as_deref(),
    )
}

fn executable_candidates_from(
    name: &str,
    path: Option<&OsStr>,
    home: Option<&Path>,
) -> Vec<PathBuf> {
    let filename = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.into()
    };
    let mut candidates: Vec<_> = path
        .into_iter()
        .flat_map(std::env::split_paths)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(&filename))
        .collect();
    if let Some(home) = home {
        candidates.extend([
            home.join(".local/bin").join(&filename),
            home.join(".bun/bin").join(&filename),
        ]);
    }
    candidates
}

pub(crate) fn executable(name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        executable_candidates(name)
            .into_iter()
            .find(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from(format!("{name}.exe")))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(name)
    }
}

pub(crate) fn executable_available(name: &str) -> bool {
    #[cfg(windows)]
    {
        executable_candidates(name)
            .iter()
            .any(|path| path.is_file())
    }
    #[cfg(not(windows))]
    {
        which::which(name).is_ok()
    }
}

pub(crate) fn child_path(base: Option<&OsStr>) -> OsString {
    let mut dirs = Vec::new();
    if let Some(home) = home_dir() {
        dirs.extend([home.join(".local/bin"), home.join(".bun/bin")]);
    }
    #[cfg(unix)]
    dirs.extend(
        [
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
        ]
        .map(PathBuf::from),
    );
    if let Some(base) = base {
        for dir in std::env::split_paths(base).filter(|dir| !dir.as_os_str().is_empty()) {
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    // Invalid PATH components should not turn a working inherited PATH into an empty one.
    std::env::join_paths(dirs).unwrap_or_else(|_| base.unwrap_or_default().to_os_string())
}

#[cfg(windows)]
pub(crate) fn powershell_installer(url: &str) -> tokio::process::Command {
    // URLs are fixed adapter constants, not user input. Keep PowerShell's configured
    // execution policy; this command never changes policy or starts a login flow.
    let mut command = tokio::process::Command::new("powershell.exe");
    command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]);
    command.arg(format!(
        "$ErrorActionPreference = 'Stop'; $global:LASTEXITCODE = 0; try {{ & ([scriptblock]::Create((Invoke-RestMethod -Uri '{url}' -ErrorAction Stop))); if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }} }} catch {{ Write-Error $_; exit 1 }}"
    ));
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_uses_native_profile_on_windows_and_ignores_empty_values() {
        assert_eq!(
            home_from(Some(OsStr::new("profile")), Some(OsStr::new("home"))),
            Some(PathBuf::from(if cfg!(windows) {
                "profile"
            } else {
                "home"
            }))
        );
        assert_eq!(
            home_from(None, Some(OsStr::new("home"))),
            Some(PathBuf::from("home"))
        );
        assert_eq!(home_from(None, Some(OsStr::new(""))), None);
    }

    #[test]
    fn executable_candidates_keep_path_order_and_native_filename() {
        let dirs = [PathBuf::from("first path"), PathBuf::from("native path")];
        let path = std::env::join_paths(&dirs).unwrap();
        let candidates =
            executable_candidates_from("fixture", Some(&path), Some(Path::new("home")));
        let filename = if cfg!(windows) {
            "fixture.exe"
        } else {
            "fixture"
        };
        assert_eq!(
            candidates,
            [
                dirs[0].join(filename),
                dirs[1].join(filename),
                Path::new("home/.local/bin").join(filename),
                Path::new("home/.bun/bin").join(filename)
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_executables_exclude_shell_shims_and_keep_later_exe_candidate() {
        let root =
            std::env::temp_dir().join(format!("agentdeck-executables-{}", uuid::Uuid::new_v4()));
        let shim = root.join("npm path");
        let native = root.join("native path");
        std::fs::create_dir_all(&shim).unwrap();
        std::fs::create_dir_all(&native).unwrap();
        std::fs::write(shim.join("fixture.cmd"), "not executed").unwrap();
        std::fs::write(native.join("fixture.exe"), "not executed").unwrap();
        let path = std::env::join_paths([&shim, &native]).unwrap();
        let actual = executable_candidates_from("fixture", Some(&path), None)
            .into_iter()
            .find(|path| path.is_file());
        assert_eq!(actual, Some(native.join("fixture.exe")));
        for name in ["fixture.cmd", "fixture.bat", "fixture.ps1", "fixture"] {
            assert!(!native_executable(Path::new(name)));
        }
        assert!(native_executable(Path::new("fixture.EXE")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn child_path_preserves_platform_separator_and_spaced_components() {
        let dir = PathBuf::from("fixture path");
        let path = std::env::join_paths([&dir]).unwrap();
        assert!(std::env::split_paths(&child_path(Some(&path))).any(|part| part == dir));
    }

    #[cfg(windows)]
    #[test]
    fn powershell_installer_propagates_download_script_and_native_exit_failures() {
        let command = powershell_installer("https://example.invalid/never-requested");
        let script = command
            .as_std()
            .get_args()
            .last()
            .unwrap()
            .to_str()
            .unwrap();
        // Override only the downloader in a fresh PowerShell process. No network,
        // installer, vendor executable, or login is touched by this fixture.
        for (download, expected) in [
            ("return 'Write-Output installed'", 0),
            ("throw 'fixture download failure'", 1),
            ("return 'throw ''fixture installer failure'''", 1),
            ("return '& $env:ComSpec /d /c exit 7'", 7),
        ] {
            let mut fixture = std::process::Command::new("powershell.exe");
            fixture.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]);
            fixture.arg(format!(
                "function Invoke-RestMethod {{ param($Uri, $ErrorAction) {download} }}; {script}"
            ));
            let output =
                crate::process::output(&mut fixture, std::time::Duration::from_secs(10)).unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
