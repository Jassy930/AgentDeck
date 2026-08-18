use std::ffi::OsStr;

pub fn real_vendor_enabled() -> bool {
    real_vendor_enabled_for(std::env::var_os("AGENTDECK_E2E").as_deref())
}

fn real_vendor_enabled_for(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

#[test]
fn real_vendor_gate_only_accepts_literal_one() {
    assert!(real_vendor_enabled_for(Some(OsStr::new("1"))));
    assert!(!real_vendor_enabled_for(None));
    for value in ["", "0", "false", "true", "yes", "2"] {
        assert!(
            !real_vendor_enabled_for(Some(OsStr::new(value))),
            "unexpectedly enabled real vendor I/O for {value:?}"
        );
    }
}
