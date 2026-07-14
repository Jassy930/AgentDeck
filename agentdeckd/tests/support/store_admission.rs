//! 限制单个 integration test binary 同时存活的真实 RuntimeStore fixture。
//!
//! 威胁场景：macOS `libtest` 在 soft FD limit 256 下并发创建多份各含 1 个 writer 与
//! 8 个 WAL reader 的真实 Store，会在业务断言执行前耗尽进程文件描述符。

use std::sync::{Condvar, Mutex};

const MAX_CONCURRENT_STORE_ROOTS: usize = 4;

static ADMISSION: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());

pub(crate) struct Permit {
    _private: (),
}

pub(crate) fn acquire() -> Permit {
    let (active, available) = &ADMISSION;
    let mut active = active
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    while *active >= MAX_CONCURRENT_STORE_ROOTS {
        active = available
            .wait(active)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    *active += 1;
    Permit { _private: () }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let (active, available) = &ADMISSION;
        let mut active = active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active = active
            .checked_sub(1)
            .expect("integration Store admission permit underflow");
        available.notify_one();
    }
}
