#[allow(dead_code)]
#[path = "../src/runtime/store/admission.rs"]
mod admission;

use admission::{
    AdmissionRejection, MIN_FILESYSTEM_RESERVE_BYTES, RUNTIME_DB_HARD_LIMIT_BYTES,
    RuntimeAdmissionInput, RuntimeCapacityProbe, RuntimeCapacityProbeError,
    SystemRuntimeCapacityProbe, evaluate_runtime_admission, evaluate_runtime_safety_admission,
    filesystem_reserve_bytes,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const PAGE_SIZE: u64 = 4096;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-admission-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create admission probe root");
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn input() -> RuntimeAdmissionInput {
    RuntimeAdmissionInput {
        main_bytes: 8 * MIB,
        wal_bytes: 2 * MIB,
        shm_bytes: MIB,
        projected_write_bytes: 4 * MIB,
        safety_margin_bytes: MIB,
        filesystem_total_bytes: 20 * GIB,
        filesystem_available_bytes: 4 * GIB,
        page_size_bytes: PAGE_SIZE,
        page_count: 2_048,
        max_page_count: RUNTIME_DB_HARD_LIMIT_BYTES / PAGE_SIZE,
    }
}

#[test]
fn hard_limit_allows_minus_one_and_exact_but_rejects_plus_one() {
    for projected in [RUNTIME_DB_HARD_LIMIT_BYTES - 1, RUNTIME_DB_HARD_LIMIT_BYTES] {
        let mut candidate = input();
        candidate.main_bytes = 0;
        candidate.wal_bytes = 0;
        candidate.shm_bytes = 0;
        candidate.page_count = 0;
        candidate.projected_write_bytes = projected;
        candidate.safety_margin_bytes = 0;
        candidate.filesystem_available_bytes = 8 * GIB;

        let admitted = evaluate_runtime_admission(candidate).expect("boundary must be admitted");
        assert_eq!(admitted.projected_footprint_bytes, projected);
    }

    let mut over = input();
    over.main_bytes = 0;
    over.wal_bytes = 0;
    over.shm_bytes = 0;
    over.page_count = 0;
    over.projected_write_bytes = RUNTIME_DB_HARD_LIMIT_BYTES + 1;
    over.safety_margin_bytes = 0;
    over.filesystem_available_bytes = 8 * GIB;
    assert!(matches!(
        evaluate_runtime_admission(over),
        Err(AdmissionRejection::DatabaseHardLimit {
            projected_footprint_bytes,
            hard_limit_bytes: RUNTIME_DB_HARD_LIMIT_BYTES,
        }) if projected_footprint_bytes == RUNTIME_DB_HARD_LIMIT_BYTES + 1
    ));
}

#[test]
fn observed_footprint_is_main_plus_wal_plus_shm() {
    let admitted = evaluate_runtime_admission(input()).expect("normal write is admitted");
    assert_eq!(admitted.observed_footprint_bytes, 11 * MIB);
    assert_eq!(admitted.growth_closure_bytes, 5 * MIB);
    assert_eq!(admitted.projected_footprint_bytes, 16 * MIB);
}

#[test]
fn every_footprint_and_growth_overflow_fails_closed() {
    let mut observed_overflow = input();
    observed_overflow.main_bytes = u64::MAX;
    observed_overflow.wal_bytes = 1;
    observed_overflow.shm_bytes = 0;
    assert!(matches!(
        evaluate_runtime_admission(observed_overflow),
        Err(AdmissionRejection::ArithmeticOverflow {
            field: "observed_footprint_bytes"
        })
    ));

    let mut growth_overflow = input();
    growth_overflow.projected_write_bytes = u64::MAX;
    growth_overflow.safety_margin_bytes = 1;
    assert!(matches!(
        evaluate_runtime_admission(growth_overflow),
        Err(AdmissionRejection::ArithmeticOverflow {
            field: "growth_closure_bytes"
        })
    ));

    let mut projected_overflow = input();
    projected_overflow.main_bytes = 1;
    projected_overflow.wal_bytes = 0;
    projected_overflow.shm_bytes = 0;
    projected_overflow.projected_write_bytes = u64::MAX;
    projected_overflow.safety_margin_bytes = 0;
    assert!(matches!(
        evaluate_runtime_admission(projected_overflow),
        Err(AdmissionRejection::ArithmeticOverflow {
            field: "projected_footprint_bytes"
        })
    ));
}

#[test]
fn filesystem_reserve_is_max_of_512_mib_and_five_percent() {
    assert_eq!(
        filesystem_reserve_bytes(4 * GIB),
        MIN_FILESYSTEM_RESERVE_BYTES
    );
    assert_eq!(filesystem_reserve_bytes(20 * GIB), GIB);
    assert_eq!(filesystem_reserve_bytes(u64::MAX), u64::MAX / 20 + 1);
}

#[test]
fn disk_must_still_have_the_reserve_after_projected_and_safety_growth() {
    let mut exact = input();
    exact.filesystem_total_bytes = 4 * GIB;
    let reserve = filesystem_reserve_bytes(exact.filesystem_total_bytes);
    let growth = exact.projected_write_bytes + exact.safety_margin_bytes;
    exact.filesystem_available_bytes = reserve + growth;
    let admitted = evaluate_runtime_admission(exact).expect("exact disk reserve is admissible");
    assert_eq!(admitted.filesystem_reserve_bytes, reserve);
    assert_eq!(admitted.available_after_growth_bytes, reserve);

    let mut low = exact;
    low.filesystem_available_bytes -= 1;
    assert!(matches!(
        evaluate_runtime_admission(low),
        Err(AdmissionRejection::DiskLow {
            available_bytes,
            required_available_bytes,
        }) if available_bytes + 1 == required_available_bytes
    ));
}

#[test]
fn safety_tail_may_consume_the_normal_filesystem_floor_but_not_its_own_obligation() {
    let mut candidate = input();
    candidate.filesystem_total_bytes = 4 * GIB;
    candidate.projected_write_bytes = 4 * MIB;
    candidate.safety_margin_bytes = MIB;
    candidate.filesystem_available_bytes = 5 * MIB;

    assert!(matches!(
        evaluate_runtime_admission(candidate),
        Err(AdmissionRejection::DiskLow { .. })
    ));
    let admitted = evaluate_runtime_safety_admission(candidate)
        .expect("reserved safety tail may consume the ordinary 512 MiB floor");
    assert_eq!(admitted.available_after_growth_bytes, 0);

    candidate.filesystem_available_bytes -= 1;
    assert!(matches!(
        evaluate_runtime_safety_admission(candidate),
        Err(AdmissionRejection::DiskLow {
            available_bytes,
            required_available_bytes,
        }) if available_bytes + 1 == required_available_bytes
    ));
}

#[test]
fn safety_tail_never_crosses_database_or_page_hard_limits() {
    let mut database_over = input();
    database_over.main_bytes = RUNTIME_DB_HARD_LIMIT_BYTES;
    database_over.wal_bytes = 0;
    database_over.shm_bytes = 0;
    database_over.page_count = 0;
    database_over.projected_write_bytes = 0;
    database_over.safety_margin_bytes = 1;
    assert!(matches!(
        evaluate_runtime_safety_admission(database_over),
        Err(AdmissionRejection::DatabaseHardLimit { .. })
    ));

    let mut page_over = input();
    page_over.main_bytes = 0;
    page_over.wal_bytes = 0;
    page_over.shm_bytes = 0;
    page_over.page_count = 100;
    page_over.max_page_count = 100;
    page_over.projected_write_bytes = 0;
    page_over.safety_margin_bytes = 1;
    assert!(matches!(
        evaluate_runtime_safety_admission(page_over),
        Err(AdmissionRejection::PageLimit {
            projected_page_count: 101,
            max_page_count: 100,
        })
    ));
}

#[test]
fn projected_pages_use_ceiling_and_must_not_cross_max_page_count() {
    let mut exact = input();
    exact.main_bytes = 99 * PAGE_SIZE;
    exact.wal_bytes = 0;
    exact.shm_bytes = 0;
    exact.page_count = 99;
    exact.max_page_count = 100;
    exact.projected_write_bytes = PAGE_SIZE;
    exact.safety_margin_bytes = 0;
    let admitted = evaluate_runtime_admission(exact).expect("exact final page is admissible");
    assert_eq!(admitted.projected_page_count, 100);

    let mut over = exact;
    over.projected_write_bytes = PAGE_SIZE + 1;
    assert!(matches!(
        evaluate_runtime_admission(over),
        Err(AdmissionRejection::PageLimit {
            projected_page_count: 101,
            max_page_count: 100,
        })
    ));
}

#[test]
fn invalid_or_unsafe_page_budget_fails_closed() {
    let mut zero_page_size = input();
    zero_page_size.page_size_bytes = 0;
    assert!(matches!(
        evaluate_runtime_admission(zero_page_size),
        Err(AdmissionRejection::InvalidPageBudget {
            reason: "page_size_zero"
        })
    ));

    let mut current_above_max = input();
    current_above_max.page_count = 101;
    current_above_max.max_page_count = 100;
    assert!(matches!(
        evaluate_runtime_admission(current_above_max),
        Err(AdmissionRejection::InvalidPageBudget {
            reason: "page_count_above_max"
        })
    ));

    let mut unsafe_max = input();
    unsafe_max.max_page_count = RUNTIME_DB_HARD_LIMIT_BYTES / PAGE_SIZE + 1;
    assert!(matches!(
        evaluate_runtime_admission(unsafe_max),
        Err(AdmissionRejection::InvalidPageBudget {
            reason: "max_page_count_above_hard_limit"
        })
    ));
}

#[test]
fn system_probe_observes_main_wal_shm_and_the_containing_filesystem() {
    let root = TestRoot::new("system-probe");
    let database = root.database();
    fs::write(&database, vec![0x11; 17]).expect("write main fixture");
    fs::write(format!("{}-wal", database.display()), vec![0x22; 23]).expect("write WAL fixture");
    fs::write(format!("{}-shm", database.display()), vec![0x33; 31]).expect("write SHM fixture");

    let observed = SystemRuntimeCapacityProbe
        .observe(&database)
        .expect("observe runtime artifacts");
    assert_eq!(observed.main_bytes, 17);
    assert_eq!(observed.wal_bytes, 23);
    assert_eq!(observed.shm_bytes, 31);
    assert!(observed.filesystem_total_bytes > 0);
    assert!(observed.filesystem_available_bytes <= observed.filesystem_total_bytes);
}

#[cfg(unix)]
#[test]
fn system_probe_rejects_a_symlinked_sidecar_instead_of_following_it() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new("symlink-sidecar");
    let database = root.database();
    let target = root.0.join("target");
    fs::write(&database, b"main").expect("write main fixture");
    fs::write(&target, b"wal").expect("write symlink target");
    let wal = PathBuf::from(format!("{}-wal", database.display()));
    symlink(&target, &wal).expect("create WAL symlink");

    let error = SystemRuntimeCapacityProbe
        .observe(&database)
        .expect_err("capacity probe must fail closed on a symlink");
    assert!(matches!(
        error,
        RuntimeCapacityProbeError::UnsafeArtifact { path } if path == wal
    ));
}
