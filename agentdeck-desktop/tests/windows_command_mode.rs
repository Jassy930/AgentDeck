//! The release target is a GUI-subsystem EXE, but --version must still work
//! when a native caller supplies only stdout. No window or vendor is started.
#![cfg(windows)]

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};

#[test]
fn desktop_version_preserves_stdout_pipe_with_missing_stderr() {
    let binary = env!("CARGO_BIN_EXE_agentdeck-desktop");
    if !cfg!(debug_assertions) {
        // This catches accidentally replacing the production GUI target with
        // a console-only fixture, which would not exercise the same startup.
        let pe = std::fs::read(binary).expect("read current desktop EXE");
        let pe_offset = u32::from_le_bytes(pe[0x3c..0x40].try_into().unwrap()) as usize;
        let subsystem = u16::from_le_bytes(
            pe[pe_offset + 24 + 68..pe_offset + 24 + 70]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            subsystem, 2,
            "release desktop must use WINDOWS_GUI subsystem"
        );
    }

    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read_pipe = null_mut();
    let mut write_pipe = null_mut();
    assert_ne!(
        unsafe { CreatePipe(&mut read_pipe, &mut write_pipe, &mut attributes, 0) },
        0,
        "CreatePipe: {}",
        std::io::Error::last_os_error()
    );
    let read_pipe = unsafe { OwnedHandle::from_raw_handle(read_pipe) };
    let write_pipe = unsafe { OwnedHandle::from_raw_handle(write_pipe) };
    assert_ne!(
        unsafe { SetHandleInformation(read_pipe.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) },
        0,
        "make read side non-inheritable: {}",
        std::io::Error::last_os_error()
    );

    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_pipe.as_raw_handle();
    // Deliberately NULL, not Stdio::null() (which would create a valid NUL
    // handle). This is the stdout-only inheritance case being regressed.
    startup.hStdError = null_mut();
    startup.hStdInput = null_mut();
    let application: Vec<u16> = OsStr::new(binary).encode_wide().chain(Some(0)).collect();
    let mut command: Vec<u16> = OsStr::new(&format!("\"{binary}\" --version"))
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut process_info: PROCESS_INFORMATION = unsafe { zeroed() };
    assert_ne!(
        unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                0,
                null(),
                null(),
                &startup,
                &mut process_info,
            )
        },
        0,
        "start current desktop --version: {}",
        std::io::Error::last_os_error()
    );
    let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess) };
    let _thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread) };
    drop(write_pipe);
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        File::from(read_pipe).read_to_string(&mut output).unwrap();
        output
    });
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle(), 10_000) };
    if wait != WAIT_OBJECT_0 {
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        unsafe { WaitForSingleObject(process.as_raw_handle(), 5_000) };
        panic!("desktop --version did not finish within 10 seconds: wait={wait}");
    }
    let mut exit_code = 0;
    assert_ne!(
        unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit_code) },
        0
    );
    assert_eq!(exit_code, 0, "desktop --version failed");
    assert_eq!(
        reader.join().unwrap(),
        format!("agentdeck-desktop {}\n", env!("CARGO_PKG_VERSION"))
    );
}
