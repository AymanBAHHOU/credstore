//! Windows.

pub mod admin;
pub mod appcontainer;
pub mod foreground;
pub mod hello;
pub mod ipc;
pub mod job;
pub mod proc;
pub mod sandbox;
pub mod service;
pub mod sig;
pub mod win;

use crate::{FeatureStatus, HardeningItem};

pub fn harden_process() -> Vec<HardeningItem> {
    let dacl = match win::protect_current_process() {
        Ok(()) => FeatureStatus::Active,
        Err(e) => FeatureStatus::Unavailable(e.to_string()),
    };
    win::disable_error_dialogs();
    vec![
        HardeningItem {
            name: "process DACL denying VM read/write/dup-handle",
            status: dacl,
        },
        HardeningItem {
            name: "WER dumps disabled",
            status: FeatureStatus::Unavailable(
                "partial: crash dialogs are off (SetErrorMode), but a machine-wide WER \
                 LocalDumps policy can still write a dump"
                    .into(),
            ),
        },
        HardeningItem {
            name: "VirtualLock",
            status: FeatureStatus::Unavailable(
                "not applied: secret values live in many small heap allocations; \
                 page file encryption is the mitigation"
                    .into(),
            ),
        },
    ]
}
