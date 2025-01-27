
use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerfEventArray},
};

use unix_sniffer_common::events::{ScmPassedFdEvent, Ucred, UnixEvent};

#[map]
pub(crate) static mut UNIXEVENT: PerfEventArray<UnixEvent> = PerfEventArray::new(0);

#[map]
pub(crate) static mut SCMEVENTS: PerfEventArray<ScmPassedFdEvent> = PerfEventArray::new(0);

#[map]
pub(crate) static mut UCREDEVENTS: PerfEventArray<Ucred> = PerfEventArray::new(0);

#[map]
pub(crate) static mut TRACKED_INODE_N: HashMap<u64, i32> = HashMap::pinned(512, 0);

#[map]
pub(crate) static mut EVENTS: PerfEventArray<ScmPassedFdEvent> = PerfEventArray::new(0);