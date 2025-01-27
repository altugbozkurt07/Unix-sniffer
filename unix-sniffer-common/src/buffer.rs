
use core::cmp::min;
use crate::macros::{bpf_target_code, not_bpf_target_code};

not_bpf_target_code! {
    mod user;
    pub use user::*;
}

//bpf_target_code! {
    mod bpf;
    pub use bpf::*;
//}


#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Buffer<const N: usize> {
    pub buf: [u8; N],
    pub len: usize,
    pub iteration_count: usize,
    pub fd_ptr: *mut i32,
}

impl<const N: usize> Default for Buffer<N> {
    fn default() -> Self {
        Self {
            buf: [0; N],
            len: 0,
            iteration_count: 0,
            fd_ptr: 0 as *mut i32,
        }
    }
}

impl<const N: usize> Buffer<N> {
    pub fn new() -> Self {
        Default::default()
    }

    pub const fn const_default() -> Self {
        Self {
            buf: [0; N],
            len: 0,
            iteration_count: 0,
            fd_ptr: 0 as *mut i32,
        }
    }

    #[inline(always)]
    pub fn copy(&mut self, other: &Self) {
        unsafe { core::ptr::copy_nonoverlapping(other as *const _, self as *mut _, 1) }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..min(self.len(), N)]
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.space_left() == 0
    }

    #[inline(always)]
    pub fn space_left(&self) -> usize {
        N - self.len
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        for i in 0..N {
            if i == self.len {
                break;
            }
            self.buf[i] = 0;
        }
        self.len = 0;
    }

    #[inline(always)]
    pub const fn cap(&self) -> usize {
        N
    }
}
