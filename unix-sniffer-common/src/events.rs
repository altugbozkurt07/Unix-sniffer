use crate::buffer::Buffer;
use crate::macros::{bpf_target_code, not_bpf_target_code};

pub const PATH_MAX: usize = 255;
pub const MAX_SEG_SIZE: usize = 500;
const TASK_COMM_LEN: usize = 16;
pub const MAX_FD_ENTRY: usize = 10*4;
pub const MAX_FD_SIZE: usize = SCM_MAX_FD * ::core::mem::size_of::<i32>();
pub const SCM_MAX_FD: usize = 253;

not_bpf_target_code! {
    mod user;
    pub use user::*;
}

//bpf_target_code! {
    mod bpf;
    pub use bpf::*;
//}


#[derive(Copy, Clone)]
#[repr(C)]
pub struct UnixEvent{
    pub pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub packet_len: u32,
    pub socket_len: u32,
    pub peer_pid: u32,
    pub data: Buffer<MAX_SEG_SIZE>,
    pub local_path: [u8; PATH_MAX],
    pub local_path_len: u32,
    pub peer_path: [u8; PATH_MAX],
    pub peer_path_len: u32,
    pub unix_inode_n: u64,
    pub blob_count: usize,
}

impl Default for UnixEvent {
    fn default() -> Self {
        UnixEvent {
            pid: 0,
            comm: [0; TASK_COMM_LEN],
            data: Buffer::<MAX_SEG_SIZE>::new(),
            local_path: [0; PATH_MAX],
            peer_path: [0; PATH_MAX],
            packet_len: 0,
            socket_len: 0,
            peer_pid: 0,
            local_path_len: 0,
            peer_path_len: 0,
            unix_inode_n: 0,
            blob_count: 0,
        }
    }
}



#[derive(Copy, Clone)]
#[repr(C)]
pub struct ScmPassedFdEvent{
    pub pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub fds: Buffer<MAX_FD_SIZE>,
}

impl Default for ScmPassedFdEvent {
    fn default() -> Self {
        ScmPassedFdEvent {
            pid: 0,
            comm: [0; TASK_COMM_LEN],
            fds: Buffer::<MAX_FD_SIZE>::new(),
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Ucred{
    pub sending_pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub sending_uid: u32,
    pub sending_gid: u32,
}

impl Default for Ucred {
    fn default() -> Self {
        Ucred {
            sending_pid: 0,
            comm: [0; TASK_COMM_LEN],
            sending_uid: 0,
            sending_gid: 0,
        }
    }
}


#[derive(Clone, Copy)]
pub enum UnixError{
    BufferFull,
    UnixAddressEmpty,
    FieldParseError,
    CmsgBufferParse,
}

impl From<i64> for UnixError{
    fn from(cause: i64) -> Self{
        UnixError::FieldParseError
    }
}