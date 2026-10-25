//! Child ownership. Windows children cannot execute before joining a private job;
//! the job stays owned after the direct child exits, so descendants remain killable.

#[cfg(not(windows))]
pub(crate) use tokio::process::Child;

#[cfg(not(windows))]
pub(crate) fn spawn(command: &mut tokio::process::Command) -> std::io::Result<Child> {
    command.spawn()
}

#[cfg(all(test, windows))]
pub(crate) use windows::tests as test_fixture;
#[cfg(windows)]
pub(crate) use windows::{Child, output, spawn};

#[cfg(windows)]
mod windows {
    use std::io;
    use std::mem::size_of;
    use std::ops::{Deref, DerefMut};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::os::windows::process::CommandExt;
    use std::process::{Output, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        TerminateProcess, WaitForSingleObject,
    };

    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
    const POLL_INTERVAL: Duration = Duration::from_millis(10);

    #[derive(Debug)]
    struct Job(OwnedHandle);

    impl Job {
        fn new() -> io::Result<Self> {
            // A null security descriptor makes this handle non-inheritable.
            let handle = unsafe { CreateJobObjectW(null(), null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // No BREAKAWAY flags: ordinary descendants inherit this job.
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    job.handle(),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        fn handle(&self) -> HANDLE {
            self.0.as_raw_handle()
        }

        fn terminate(&self) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.handle(), 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn is_empty(&self) -> io::Result<bool> {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            if unsafe {
                QueryInformationJobObject(
                    self.handle(),
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(accounting.ActiveProcesses == 0)
        }

        fn terminate_and_wait(&self, timeout: Duration) -> io::Result<()> {
            self.terminate()?;
            let deadline = Instant::now() + timeout;
            while !self.is_empty()? {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Windows job still contains active processes after termination",
                    ));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Ok(())
        }
    }

    /// `CREATE_SUSPENDED` leaves only the primary thread before any user code.
    /// Tokio/std do not expose its handle, so use the documented Toolhelp API.
    fn resume_primary_thread(pid: u32) -> io::Result<()> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut found = None;
        let mut present = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
        while present != 0 {
            if entry.th32OwnerProcessID == pid {
                if found.replace(entry.th32ThreadID).is_some() {
                    return Err(io::Error::other(
                        "suspended child has multiple threads; refusing to guess the primary thread",
                    ));
                }
            }
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            present = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
            return Err(error);
        }
        let thread_id =
            found.ok_or_else(|| io::Error::other("suspended child thread not found"))?;
        let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
        if thread.is_null() {
            return Err(io::Error::last_os_error());
        }
        let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
        match unsafe { ResumeThread(thread.as_raw_handle()) } {
            1 => Ok(()),
            u32::MAX => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected suspended child thread state")),
        }
    }

    fn admit(
        job: &Job,
        process: HANDLE,
        pid: u32,
        resume: impl FnOnce(u32) -> io::Result<()>,
    ) -> io::Result<()> {
        let result = if unsafe { AssignProcessToJobObject(job.handle(), process) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            resume(pid)
        };
        if let Err(error) = result {
            // Assignment failure must not allow the suspended child to run.
            let _ = job.terminate();
            unsafe { TerminateProcess(process, 1) };
            if unsafe { WaitForSingleObject(process, CLEANUP_TIMEOUT.as_millis() as u32) }
                != WAIT_OBJECT_0
            {
                return Err(io::Error::other(format!(
                    "Windows job admission failed ({error}); child termination was not confirmed"
                )));
            }
            return Err(io::Error::new(
                error.kind(),
                format!("Windows job admission failed before launch: {error}"),
            ));
        }
        Ok(())
    }

    #[derive(Debug)]
    pub(crate) struct Child {
        child: tokio::process::Child,
        // Closing the final job handle also kills descendants if a task is aborted.
        job: Job,
    }

    impl Deref for Child {
        type Target = tokio::process::Child;

        fn deref(&self) -> &Self::Target {
            &self.child
        }
    }

    impl DerefMut for Child {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.child
        }
    }

    impl Child {
        pub(crate) fn terminate_tree(&self) -> io::Result<()> {
            self.job.terminate()
        }

        pub(crate) fn tree_is_empty(&self) -> io::Result<bool> {
            self.job.is_empty()
        }

        pub(crate) async fn terminate_tree_and_wait(
            &mut self,
            timeout: Duration,
        ) -> io::Result<()> {
            self.terminate_tree()?;
            tokio::time::timeout(timeout, async {
                self.child.wait().await?;
                while !self.tree_is_empty()? {
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                Ok(())
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Windows child or its job did not terminate within the cleanup deadline",
                )
            })?
        }
    }

    pub(crate) fn spawn(command: &mut tokio::process::Command) -> io::Result<Child> {
        let job = Job::new()?;
        let child = command
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
            .kill_on_drop(true)
            .spawn()?;
        // A newly spawned suspended child has not been polled/reaped.
        let process = child
            .raw_handle()
            .ok_or_else(|| io::Error::other("new Windows child is missing its process handle"))?;
        let pid = child
            .id()
            .ok_or_else(|| io::Error::other("new Windows child is missing its process id"))?;
        admit(&job, process, pid, resume_primary_thread)?;
        Ok(Child { child, job })
    }

    /// Synchronous probes keep the job while a worker drains both pipes; a slow
    /// probe or descendant holding a pipe cannot block its caller indefinitely.
    pub(crate) fn output(
        command: &mut std::process::Command,
        timeout: Duration,
    ) -> io::Result<Output> {
        let job = Job::new()?;
        let child = command
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        admit(
            &job,
            child.as_raw_handle(),
            child.id(),
            resume_primary_thread,
        )?;
        let (send, receive) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("agentdeck-process-output".into())
            .spawn(move || {
                let _ = send.send(child.wait_with_output());
            })?;
        let result = receive.recv_timeout(timeout);
        // Even a successfully exited direct child can leave descendants behind.
        job.terminate_and_wait(CLEANUP_TIMEOUT)?;
        match result {
            Ok(output) => {
                worker
                    .join()
                    .map_err(|_| io::Error::other("process output worker panicked"))?;
                output
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Killing the job closes inherited pipes; wait for worker cleanup too.
                let _ = receive.recv_timeout(CLEANUP_TIMEOUT);
                if worker.is_finished() {
                    let _ = worker.join();
                }
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Windows process probe timed out",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = worker.join();
                Err(io::Error::other("process output worker disconnected"))
            }
        }
    }

    #[cfg(test)]
    pub(crate) mod tests {
        use super::*;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};
        use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };

        const FIXTURE: &str = "process::windows::tests::job_fixture";
        const MODE: &str = "AGENTDECK_JOB_TEST_MODE";
        const DIRECTORY: &str = "AGENTDECK_JOB_TEST_DIRECTORY";

        pub(crate) fn directory() -> PathBuf {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "agentdeck-job-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        pub(crate) fn fixture_command(mode: &str, dir: &Path) -> std::process::Command {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", FIXTURE, "--nocapture"])
                .env(MODE, mode)
                .env(DIRECTORY, dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        }

        pub(crate) async fn descendants(dir: &Path) -> [u32; 2] {
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let read_pid = |name: &str| {
                        std::fs::read_to_string(dir.join(name))
                            .ok()
                            .and_then(|value| value.parse::<u32>().ok())
                    };
                    if let (Some(branch), Some(leaf)) =
                        (read_pid("branch.pid"), read_pid("leaf.pid"))
                    {
                        return [branch, leaf];
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            })
            .await
            .expect("fixture must launch both descendants")
        }

        fn process_handle(pid: u32) -> io::Result<OwnedHandle> {
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
        }

        pub(crate) fn assert_exited(pid: u32) {
            match process_handle(pid) {
                Ok(handle) => assert_eq!(
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 5000) },
                    WAIT_OBJECT_0,
                    "fixture process {pid} survived job cleanup"
                ),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(ERROR_INVALID_PARAMETER as i32))
                }
            }
        }

        /// Only explicit subprocess invocations enter this fixture; ordinary test
        /// discovery does nothing and never starts a vendor executable.
        #[test]
        fn job_fixture() {
            let Ok(mode) = std::env::var(MODE) else {
                return;
            };
            let dir = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
            std::fs::write(
                dir.join(format!("{mode}.pid")),
                std::process::id().to_string(),
            )
            .unwrap();
            if mode == "emit" {
                println!("fixture stdout");
                eprintln!("fixture stderr");
                println!("{}", "o".repeat(131_072));
                eprintln!("{}", "e".repeat(131_072));
                return;
            }
            let next = match mode.as_str() {
                "root-exit" | "root-stay" => Some("branch"),
                "branch" => Some("leaf"),
                "leaf" => None,
                _ => panic!("unexpected fixture mode"),
            };
            if let Some(next) = next {
                // std::Child drop intentionally leaves the descendant running.
                drop(fixture_command(next, &dir).spawn().unwrap());
            }
            if mode == "root-exit" {
                return;
            }
            // A failed test cannot leave the fixture running indefinitely.
            std::thread::sleep(Duration::from_secs(60));
        }

        #[tokio::test]
        async fn reaped_direct_child_keeps_descendants_owned_until_confirmed_cleanup() {
            let dir = directory();
            let mut command: tokio::process::Command = fixture_command("root-exit", &dir).into();
            let mut child = spawn(&mut command).unwrap();
            let pids = descendants(&dir).await;
            child.wait().await.unwrap();
            assert!(child.id().is_none());
            assert!(!child.tree_is_empty().unwrap());
            child
                .terminate_tree_and_wait(CLEANUP_TIMEOUT)
                .await
                .unwrap();
            assert!(child.tree_is_empty().unwrap());
            for pid in pids {
                assert_exited(pid);
            }
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn dropping_child_kills_the_owned_process_tree() {
            let dir = directory();
            let mut command: tokio::process::Command = fixture_command("root-stay", &dir).into();
            let child = spawn(&mut command).unwrap();
            let pids = descendants(&dir).await;
            let handles: Vec<_> = [child.id().unwrap(), pids[0], pids[1]]
                .into_iter()
                .map(|pid| process_handle(pid).unwrap())
                .collect();
            for handle in &handles {
                assert_eq!(
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) },
                    WAIT_TIMEOUT
                );
            }
            drop(child);
            for handle in handles {
                assert_eq!(
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 5000) },
                    WAIT_OBJECT_0
                );
            }
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn failed_admission_never_runs_the_suspended_child() {
            let dir = directory();
            let job = Job::new().unwrap();
            let mut child = fixture_command("leaf", &dir)
                .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
                .spawn()
                .unwrap();
            let error = admit(&job, child.as_raw_handle(), child.id(), |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture denied resume",
                ))
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(!child.wait().unwrap().success());
            assert!(!dir.join("leaf.pid").exists());
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn denied_job_assignment_terminates_child_before_any_user_code() {
            let dir = directory();
            let job = Job::new().unwrap();
            let mut child = fixture_command("leaf", &dir)
                .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
                .spawn()
                .unwrap();
            // Assignment requires PROCESS_SET_QUOTA as well as PROCESS_TERMINATE.
            // Keep only termination/wait rights to exercise an actual Win32 denial.
            let restricted =
                unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, child.id()) };
            assert!(!restricted.is_null());
            let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
            let error = admit(&job, restricted.as_raw_handle(), child.id(), |_| {
                panic!("a child denied admission must never be resumed")
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(!child.wait().unwrap().success());
            assert!(!dir.join("leaf.pid").exists());
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn synchronous_output_drains_both_pipes() {
            let dir = directory();
            let result =
                output(&mut fixture_command("emit", &dir), Duration::from_secs(10)).unwrap();
            assert!(result.status.success());
            assert!(String::from_utf8_lossy(&result.stdout).contains("fixture stdout"));
            assert!(String::from_utf8_lossy(&result.stderr).contains("fixture stderr"));
            assert!(result.stdout.len() > 131_072);
            assert!(result.stderr.len() > 131_072);
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn synchronous_probe_timeout_kills_descendants() {
            let dir = directory();
            let child_dir = dir.clone();
            let worker = std::thread::spawn(move || {
                output(
                    &mut fixture_command("root-stay", &child_dir),
                    Duration::from_secs(5),
                )
            });
            let pids = descendants(&dir).await;
            let error = worker.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            for pid in pids {
                assert_exited(pid);
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
