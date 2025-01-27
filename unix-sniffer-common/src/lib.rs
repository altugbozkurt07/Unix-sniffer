#![cfg_attr(target_arch = "bpf", no_std)]

mod buffer;
pub mod events;
mod macros;
pub mod utils;
pub mod alloc;
pub mod co_re;
mod version;