//! Runtime SQLite 写入的纯 admission 计算。
//!
//! 本模块不读取文件系统、不执行 checkpoint，也不修改 SQLite。调用方先采集同一
//! admission 时点的 main/WAL/SHM、文件系统与 page budget，再把保守 projected write
//! 和 safety margin 一并传入。任何算术、page 配置或容量不一致都 fail-close。

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;

/// Runtime DB 的 main + WAL + SHM 写后物理硬上界。
pub const RUNTIME_DB_HARD_LIMIT_BYTES: u64 = 2 * GIB;
/// 文件系统始终保留的绝对下界。
pub const MIN_FILESYSTEM_RESERVE_BYTES: u64 = 512 * MIB;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCapacityObservation {
    pub main_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
    pub filesystem_total_bytes: u64,
    pub filesystem_available_bytes: u64,
}

pub trait RuntimeCapacityProbe: Send + Sync {
    fn observe(
        &self,
        database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRuntimeCapacityProbe;

#[derive(Debug)]
pub enum RuntimeCapacityProbeError {
    MissingParent {
        path: PathBuf,
    },
    PathContainsNul {
        path: PathBuf,
    },
    UnsafeArtifact {
        path: PathBuf,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    UnsupportedPlatform,
}

impl fmt::Display for RuntimeCapacityProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingParent { path } => write!(
                formatter,
                "runtime capacity path has no parent: {}",
                path.display()
            ),
            Self::PathContainsNul { path } => write!(
                formatter,
                "runtime capacity path contains NUL: {}",
                path.display()
            ),
            Self::UnsafeArtifact { path } => write!(
                formatter,
                "runtime capacity artifact is not a regular file: {}",
                path.display()
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "runtime capacity arithmetic overflow: {field}")
            }
            Self::Io { path, source } => write!(
                formatter,
                "runtime capacity observation failed for {}: {source}",
                path.display()
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("runtime capacity observation is unsupported on this platform")
            }
        }
    }
}

impl Error for RuntimeCapacityProbeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl RuntimeCapacityProbe for SystemRuntimeCapacityProbe {
    fn observe(
        &self,
        database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        let wal = sidecar_path(database, "-wal");
        let shm = sidecar_path(database, "-shm");
        let main_bytes = artifact_bytes(database, true)?;
        let wal_bytes = artifact_bytes(&wal, false)?;
        let shm_bytes = artifact_bytes(&shm, false)?;
        let parent = database
            .parent()
            .ok_or_else(|| RuntimeCapacityProbeError::MissingParent {
                path: database.to_path_buf(),
            })?;
        let (filesystem_total_bytes, filesystem_available_bytes) = filesystem_bytes(parent)?;
        Ok(RuntimeCapacityObservation {
            main_bytes,
            wal_bytes,
            shm_bytes,
            filesystem_total_bytes,
            filesystem_available_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeAdmissionState {
    Normal,
    SafetyOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAdmissionInput {
    pub main_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
    /// 本次事务的保守物理增长估算。
    pub projected_write_bytes: u64,
    /// 覆盖 page/WAL 对齐、checkpoint 暂时不可回收等不确定性的安全闭包。
    pub safety_margin_bytes: u64,
    pub filesystem_total_bytes: u64,
    pub filesystem_available_bytes: u64,
    pub page_size_bytes: u64,
    pub page_count: u64,
    pub max_page_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAdmission {
    pub observed_footprint_bytes: u64,
    pub growth_closure_bytes: u64,
    pub projected_footprint_bytes: u64,
    pub filesystem_reserve_bytes: u64,
    pub available_after_growth_bytes: u64,
    pub projected_page_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRejection {
    ArithmeticOverflow {
        field: &'static str,
    },
    DatabaseHardLimit {
        projected_footprint_bytes: u64,
        hard_limit_bytes: u64,
    },
    DiskLow {
        available_bytes: u64,
        required_available_bytes: u64,
    },
    InvalidPageBudget {
        reason: &'static str,
    },
    PageLimit {
        projected_page_count: u64,
        max_page_count: u64,
    },
}

/// `max(512 MiB, filesystem_total * 5%)`。
///
/// 5% 精确等于 `1/20`，向上取整，避免因整数截断少保留 1–19 bytes；先除后加避免
/// `filesystem_total * 5` 在极大输入上溢出。
#[must_use]
pub const fn filesystem_reserve_bytes(filesystem_total_bytes: u64) -> u64 {
    let percentage = filesystem_total_bytes.div_ceil(20);
    if percentage > MIN_FILESYSTEM_RESERVE_BYTES {
        percentage
    } else {
        MIN_FILESYSTEM_RESERVE_BYTES
    }
}

/// 对一次普通有副作用写执行 fail-closed admission 判定。
pub fn evaluate_runtime_admission(
    input: RuntimeAdmissionInput,
) -> Result<RuntimeAdmission, AdmissionRejection> {
    let observed_footprint_bytes = input
        .main_bytes
        .checked_add(input.wal_bytes)
        .and_then(|bytes| bytes.checked_add(input.shm_bytes))
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "observed_footprint_bytes",
        })?;
    let growth_closure_bytes = input
        .projected_write_bytes
        .checked_add(input.safety_margin_bytes)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "growth_closure_bytes",
        })?;
    let projected_footprint_bytes = observed_footprint_bytes
        .checked_add(growth_closure_bytes)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "projected_footprint_bytes",
        })?;

    validate_page_budget(input)?;

    if projected_footprint_bytes > RUNTIME_DB_HARD_LIMIT_BYTES {
        return Err(AdmissionRejection::DatabaseHardLimit {
            projected_footprint_bytes,
            hard_limit_bytes: RUNTIME_DB_HARD_LIMIT_BYTES,
        });
    }

    let filesystem_reserve_bytes = filesystem_reserve_bytes(input.filesystem_total_bytes);
    let required_available_bytes = filesystem_reserve_bytes
        .checked_add(growth_closure_bytes)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "required_available_bytes",
        })?;
    if input.filesystem_available_bytes < required_available_bytes {
        return Err(AdmissionRejection::DiskLow {
            available_bytes: input.filesystem_available_bytes,
            required_available_bytes,
        });
    }
    let available_after_growth_bytes = input
        .filesystem_available_bytes
        .checked_sub(growth_closure_bytes)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "available_after_growth_bytes",
        })?;

    let growth_pages = ceil_div(growth_closure_bytes, input.page_size_bytes)?;
    let projected_page_count = input.page_count.checked_add(growth_pages).ok_or(
        AdmissionRejection::ArithmeticOverflow {
            field: "projected_page_count",
        },
    )?;
    if projected_page_count > input.max_page_count {
        return Err(AdmissionRejection::PageLimit {
            projected_page_count,
            max_page_count: input.max_page_count,
        });
    }

    Ok(RuntimeAdmission {
        observed_footprint_bytes,
        growth_closure_bytes,
        projected_footprint_bytes,
        filesystem_reserve_bytes,
        available_after_growth_bytes,
        projected_page_count,
    })
}

/// 对已经由普通写预留的 safety tail 做消费前校验。
///
/// safety 写允许消耗普通准入保留的文件系统 512 MiB/5% 区域，因此这里只要求当前可用空间
/// 覆盖剩余 safety obligation；DB 物理 footprint 与 page budget 仍不得越过 2 GiB。
pub fn evaluate_runtime_safety_admission(
    input: RuntimeAdmissionInput,
) -> Result<RuntimeAdmission, AdmissionRejection> {
    let observed_footprint_bytes = input
        .main_bytes
        .checked_add(input.wal_bytes)
        .and_then(|bytes| bytes.checked_add(input.shm_bytes))
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "observed_footprint_bytes",
        })?;
    let growth_closure_bytes = input
        .projected_write_bytes
        .checked_add(input.safety_margin_bytes)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "growth_closure_bytes",
        })?;
    let projected_footprint_bytes = observed_footprint_bytes
        .checked_add(growth_closure_bytes)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "projected_footprint_bytes",
        })?;
    validate_page_budget(input)?;
    if projected_footprint_bytes > RUNTIME_DB_HARD_LIMIT_BYTES {
        return Err(AdmissionRejection::DatabaseHardLimit {
            projected_footprint_bytes,
            hard_limit_bytes: RUNTIME_DB_HARD_LIMIT_BYTES,
        });
    }
    if input.filesystem_available_bytes < growth_closure_bytes {
        return Err(AdmissionRejection::DiskLow {
            available_bytes: input.filesystem_available_bytes,
            required_available_bytes: growth_closure_bytes,
        });
    }
    let available_after_growth_bytes = input
        .filesystem_available_bytes
        .checked_sub(growth_closure_bytes)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "available_after_growth_bytes",
        })?;
    let growth_pages = ceil_div(growth_closure_bytes, input.page_size_bytes)?;
    let projected_page_count = input.page_count.checked_add(growth_pages).ok_or(
        AdmissionRejection::ArithmeticOverflow {
            field: "projected_page_count",
        },
    )?;
    if projected_page_count > input.max_page_count {
        return Err(AdmissionRejection::PageLimit {
            projected_page_count,
            max_page_count: input.max_page_count,
        });
    }
    Ok(RuntimeAdmission {
        observed_footprint_bytes,
        growth_closure_bytes,
        projected_footprint_bytes,
        filesystem_reserve_bytes: 0,
        available_after_growth_bytes,
        projected_page_count,
    })
}

fn validate_page_budget(input: RuntimeAdmissionInput) -> Result<(), AdmissionRejection> {
    if input.page_size_bytes == 0 {
        return Err(AdmissionRejection::InvalidPageBudget {
            reason: "page_size_zero",
        });
    }
    if input.max_page_count == 0 {
        return Err(AdmissionRejection::InvalidPageBudget {
            reason: "max_page_count_zero",
        });
    }
    if input.page_count > input.max_page_count {
        return Err(AdmissionRejection::InvalidPageBudget {
            reason: "page_count_above_max",
        });
    }
    let hard_max_pages = RUNTIME_DB_HARD_LIMIT_BYTES / input.page_size_bytes;
    if input.max_page_count > hard_max_pages {
        return Err(AdmissionRejection::InvalidPageBudget {
            reason: "max_page_count_above_hard_limit",
        });
    }
    Ok(())
}

fn ceil_div(numerator: u64, denominator: u64) -> Result<u64, AdmissionRejection> {
    if denominator == 0 {
        return Err(AdmissionRejection::InvalidPageBudget {
            reason: "page_size_zero",
        });
    }
    let quotient = numerator / denominator;
    let extra = u64::from(!numerator.is_multiple_of(denominator));
    quotient
        .checked_add(extra)
        .ok_or(AdmissionRejection::ArithmeticOverflow {
            field: "projected_growth_pages",
        })
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
}

fn artifact_bytes(path: &Path, required: bool) -> Result<u64, RuntimeCapacityProbeError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(source) => {
            return Err(RuntimeCapacityProbeError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(RuntimeCapacityProbeError::UnsafeArtifact {
            path: path.to_path_buf(),
        });
    }
    Ok(metadata.len())
}

#[cfg(unix)]
fn filesystem_bytes(path: &Path) -> Result<(u64, u64), RuntimeCapacityProbeError> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    let native = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        RuntimeCapacityProbeError::PathContainsNul {
            path: path.to_path_buf(),
        }
    })?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `native` is NUL-terminated and `stat` points to writable, properly aligned storage.
    if unsafe { libc::statvfs(native.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(RuntimeCapacityProbeError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: a zero return from `statvfs` initializes the entire output struct.
    let stat = unsafe { stat.assume_init() };
    let fragment_size = if stat.f_frsize == 0 {
        stat.f_bsize
    } else {
        stat.f_frsize
    };
    let fragment_size: u64 = fragment_size;
    let blocks: u64 = stat.f_blocks.into();
    let available_blocks: u64 = stat.f_bavail.into();
    let total =
        blocks
            .checked_mul(fragment_size)
            .ok_or(RuntimeCapacityProbeError::ArithmeticOverflow {
                field: "filesystem_total_bytes",
            })?;
    let available = available_blocks.checked_mul(fragment_size).ok_or(
        RuntimeCapacityProbeError::ArithmeticOverflow {
            field: "filesystem_available_bytes",
        },
    )?;
    Ok((total, available))
}

#[cfg(not(unix))]
fn filesystem_bytes(_path: &Path) -> Result<(u64, u64), RuntimeCapacityProbeError> {
    Err(RuntimeCapacityProbeError::UnsupportedPlatform)
}
