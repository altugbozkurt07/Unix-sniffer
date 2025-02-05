/* automatically generated by rust-bindgen 0.70.1 */

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::core::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::core::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::core::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::core::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
pub type __u32 = ::core::ffi::c_uint;
pub type __u8 = ::core::ffi::c_uchar;
pub type u8_ = __u8;
pub type __s32 = ::core::ffi::c_int;
pub type __kernel_ulong_t = ::core::ffi::c_ulong;
pub type __kernel_size_t = __kernel_ulong_t;
pub type size_t = __kernel_size_t;
extern "C" {
    pub fn shim_iter_type_ITER_IOVEC() -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iter_type_ITER_IOVEC_exists() -> bool;
}
extern "C" {
    pub fn shim_iter_type_ITER_KVEC() -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iter_type_ITER_KVEC_exists() -> bool;
}
extern "C" {
    pub fn shim_iter_type_ITER_BVEC() -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iter_type_ITER_BVEC_exists() -> bool;
}
extern "C" {
    pub fn shim_iter_type_ITER_PIPE() -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iter_type_ITER_PIPE_exists() -> bool;
}
extern "C" {
    pub fn shim_iter_type_ITER_XARRAY() -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iter_type_ITER_XARRAY_exists() -> bool;
}
extern "C" {
    pub fn shim_iter_type_ITER_DISCARD() -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iter_type_ITER_DISCARD_exists() -> bool;
}
extern "C" {
    pub fn shim_iter_type_ITER_UBUF() -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iter_type_ITER_UBUF_exists() -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct iov_iter {
    pub __bindgen_anon_1: iov_iter__bindgen_ty_1,
    pub count: size_t,
    pub __bindgen_anon_2: iov_iter__bindgen_ty_2,
    pub __bindgen_anon_3: iov_iter__bindgen_ty_3,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union iov_iter__bindgen_ty_1 {
    pub iter_type: u8_,
    pub type_: ::core::ffi::c_uint,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union iov_iter__bindgen_ty_2 {
    pub iov: *mut iovec,
    pub __iov: *mut iovec,
    pub ubuf: *mut ::core::ffi::c_void,
    pub bvec: *mut bio_vec,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union iov_iter__bindgen_ty_3 {
    pub nr_segs: ::core::ffi::c_ulong,
}
extern "C" {
    pub fn shim_iov_iter_iter_type(iov_iter: *mut iov_iter) -> ::core::ffi::c_uchar;
}
extern "C" {
    pub fn shim_iov_iter_iter_type_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_uchar;
}
extern "C" {
    pub fn shim_iov_iter_iter_type_exists(iov_iter: *mut iov_iter) -> bool;
}
extern "C" {
    pub fn shim_iov_iter_type(iov_iter: *mut iov_iter) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iov_iter_type_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_iov_iter_type_exists(iov_iter: *mut iov_iter) -> bool;
}
extern "C" {
    pub fn shim_iov_iter_count(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_iov_iter_count_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_iov_iter_count_exists(iov_iter: *mut iov_iter) -> bool;
}
extern "C" {
    pub fn shim_iov_iter_nr_segs(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_iov_iter_nr_segs_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_iov_iter_nr_segs_exists(iov_iter: *mut iov_iter) -> bool;
}
extern "C" {
    pub fn shim_iov_iter_ubuf(iov_iter: *mut iov_iter) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_iov_iter_ubuf_user(iov_iter: *mut iov_iter) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_iov_iter_ubuf_exists(iov_iter: *mut iov_iter) -> bool;
}
extern "C" {
    pub fn shim_iov_iter_iov(iov_iter: *mut iov_iter) -> *mut iovec;
}
extern "C" {
    pub fn shim_iov_iter_iov_user(iov_iter: *mut iov_iter) -> *mut iovec;
}
extern "C" {
    pub fn shim_iov_iter_iov_exists(iov_iter: *mut iov_iter) -> bool;
}
extern "C" {
    pub fn shim_iov_iter___iov(iov_iter: *mut iov_iter) -> *mut iovec;
}
extern "C" {
    pub fn shim_iov_iter___iov_user(iov_iter: *mut iov_iter) -> *mut iovec;
}
extern "C" {
    pub fn shim_iov_iter___iov_exists(iov_iter: *mut iov_iter) -> bool;
}
extern "C" {
    pub fn shim_iov_iter_bvec(iov_iter: *mut iov_iter) -> *mut bio_vec;
}
extern "C" {
    pub fn shim_iov_iter_bvec_user(iov_iter: *mut iov_iter) -> *mut bio_vec;
}
extern "C" {
    pub fn shim_iov_iter_bvec_exists(iov_iter: *mut iov_iter) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut ::core::ffi::c_void,
    pub iov_len: __kernel_size_t,
}
extern "C" {
    pub fn shim_iovec_iov_base(iovec: *mut iovec) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_iovec_iov_base_user(iovec: *mut iovec) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_iovec_iov_base_exists(iovec: *mut iovec) -> bool;
}
extern "C" {
    pub fn shim_iovec_iov_len(iovec: *mut iovec) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_iovec_iov_len_user(iovec: *mut iovec) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_iovec_iov_len_exists(iovec: *mut iovec) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cmsghdr {
    pub cmsg_len: size_t,
    pub cmsg_level: ::core::ffi::c_int,
    pub cmsg_type: ::core::ffi::c_int,
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_len(cmsghdr: *mut cmsghdr) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_len_user(cmsghdr: *mut cmsghdr) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_len_exists(cmsghdr: *mut cmsghdr) -> bool;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_level(cmsghdr: *mut cmsghdr) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_level_user(cmsghdr: *mut cmsghdr) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_level_exists(cmsghdr: *mut cmsghdr) -> bool;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_type(cmsghdr: *mut cmsghdr) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_type_user(cmsghdr: *mut cmsghdr) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_cmsghdr_cmsg_type_exists(cmsghdr: *mut cmsghdr) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct msghdr {
    pub msg_iter: iov_iter,
    pub msg_controllen: __kernel_size_t,
    pub msg_control: *mut ::core::ffi::c_void,
}
extern "C" {
    pub fn shim_msghdr_msg_iter(msghdr: *mut msghdr) -> *mut iov_iter;
}
extern "C" {
    pub fn shim_msghdr_msg_iter_user(msghdr: *mut msghdr) -> *mut iov_iter;
}
extern "C" {
    pub fn shim_msghdr_msg_iter_exists(msghdr: *mut msghdr) -> bool;
}
extern "C" {
    pub fn shim_msghdr_msg_control(msghdr: *mut msghdr) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_msghdr_msg_control_user(msghdr: *mut msghdr) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_msghdr_msg_control_exists(msghdr: *mut msghdr) -> bool;
}
extern "C" {
    pub fn shim_msghdr_msg_controllen(msghdr: *mut msghdr) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_msghdr_msg_controllen_user(msghdr: *mut msghdr) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_msghdr_msg_controllen_exists(msghdr: *mut msghdr) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sock_common {
    pub skc_family: ::core::ffi::c_ushort,
}
extern "C" {
    pub fn shim_sock_common_skc_family(sock_common: *mut sock_common) -> ::core::ffi::c_ushort;
}
extern "C" {
    pub fn shim_sock_common_skc_family_user(sock_common: *mut sock_common)
        -> ::core::ffi::c_ushort;
}
extern "C" {
    pub fn shim_sock_common_skc_family_exists(sock_common: *mut sock_common) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct upid {
    pub nr: __s32,
}
extern "C" {
    pub fn shim_upid_nr(upid: *mut upid) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_upid_nr_user(upid: *mut upid) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_upid_nr_exists(upid: *mut upid) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pid {
    pub numbers: [upid; 1usize],
}
extern "C" {
    pub fn shim_pid_numbers(pid: *mut pid) -> *mut upid;
}
extern "C" {
    pub fn shim_pid_numbers_user(pid: *mut pid) -> *mut upid;
}
extern "C" {
    pub fn shim_pid_numbers_exists(pid: *mut pid) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sock {
    pub __sk_common: sock_common,
    pub sk_peer_pid: *mut pid,
}
extern "C" {
    pub fn shim_sock___sk_common(sock: *mut sock) -> *mut sock_common;
}
extern "C" {
    pub fn shim_sock___sk_common_user(sock: *mut sock) -> *mut sock_common;
}
extern "C" {
    pub fn shim_sock___sk_common_exists(sock: *mut sock) -> bool;
}
extern "C" {
    pub fn shim_sock_sk_peer_pid(sock: *mut sock) -> *mut pid;
}
extern "C" {
    pub fn shim_sock_sk_peer_pid_user(sock: *mut sock) -> *mut pid;
}
extern "C" {
    pub fn shim_sock_sk_peer_pid_exists(sock: *mut sock) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct socket {
    pub sk: *mut sock,
}
extern "C" {
    pub fn shim_socket_sk(socket: *mut socket) -> *mut sock;
}
extern "C" {
    pub fn shim_socket_sk_user(socket: *mut socket) -> *mut sock;
}
extern "C" {
    pub fn shim_socket_sk_exists(socket: *mut socket) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_un {
    pub sun_path: [::core::ffi::c_char; 108usize],
}
extern "C" {
    pub fn shim_sockaddr_un_sun_path(sockaddr_un: *mut sockaddr_un) -> *mut ::core::ffi::c_char;
}
extern "C" {
    pub fn shim_sockaddr_un_sun_path_user(
        sockaddr_un: *mut sockaddr_un,
    ) -> *mut ::core::ffi::c_char;
}
extern "C" {
    pub fn shim_sockaddr_un_sun_path_exists(sockaddr_un: *mut sockaddr_un) -> bool;
}
#[repr(C)]
#[derive(Debug)]
pub struct unix_address {
    pub len: __s32,
    pub name: __IncompleteArrayField<sockaddr_un>,
}
extern "C" {
    pub fn shim_unix_address_len(unix_address: *mut unix_address) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_unix_address_len_user(unix_address: *mut unix_address) -> ::core::ffi::c_int;
}
extern "C" {
    pub fn shim_unix_address_len_exists(unix_address: *mut unix_address) -> bool;
}
extern "C" {
    pub fn shim_unix_address_name(unix_address: *mut unix_address) -> *mut [sockaddr_un; 0usize];
}
extern "C" {
    pub fn shim_unix_address_name_user(
        unix_address: *mut unix_address,
    ) -> *mut [sockaddr_un; 0usize];
}
extern "C" {
    pub fn shim_unix_address_name_exists(unix_address: *mut unix_address) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct inode {
    pub i_ino: ::core::ffi::c_ulong,
}
extern "C" {
    pub fn shim_inode_i_ino(inode: *mut inode) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_inode_i_ino_user(inode: *mut inode) -> ::core::ffi::c_ulong;
}
extern "C" {
    pub fn shim_inode_i_ino_exists(inode: *mut inode) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dentry {
    pub d_inode: *mut inode,
}
extern "C" {
    pub fn shim_dentry_d_inode(dentry: *mut dentry) -> *mut inode;
}
extern "C" {
    pub fn shim_dentry_d_inode_user(dentry: *mut dentry) -> *mut inode;
}
extern "C" {
    pub fn shim_dentry_d_inode_exists(dentry: *mut dentry) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct path {
    pub dentry: *mut dentry,
}
extern "C" {
    pub fn shim_path_dentry(path: *mut path) -> *mut dentry;
}
extern "C" {
    pub fn shim_path_dentry_user(path: *mut path) -> *mut dentry;
}
extern "C" {
    pub fn shim_path_dentry_exists(path: *mut path) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct unix_sock {
    pub peer: *mut sock,
    pub addr: *mut unix_address,
    pub path: path,
}
extern "C" {
    pub fn shim_unix_sock_peer(unix_sock: *mut unix_sock) -> *mut sock;
}
extern "C" {
    pub fn shim_unix_sock_peer_user(unix_sock: *mut unix_sock) -> *mut sock;
}
extern "C" {
    pub fn shim_unix_sock_peer_exists(unix_sock: *mut unix_sock) -> bool;
}
extern "C" {
    pub fn shim_unix_sock_addr(unix_sock: *mut unix_sock) -> *mut unix_address;
}
extern "C" {
    pub fn shim_unix_sock_addr_user(unix_sock: *mut unix_sock) -> *mut unix_address;
}
extern "C" {
    pub fn shim_unix_sock_addr_exists(unix_sock: *mut unix_sock) -> bool;
}
extern "C" {
    pub fn shim_unix_sock_path(unix_sock: *mut unix_sock) -> *mut path;
}
extern "C" {
    pub fn shim_unix_sock_path_user(unix_sock: *mut unix_sock) -> *mut path;
}
extern "C" {
    pub fn shim_unix_sock_path_exists(unix_sock: *mut unix_sock) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct file {
    pub f_inode: *mut inode,
    pub f_path: path,
    pub private_data: *mut ::core::ffi::c_void,
}
extern "C" {
    pub fn shim_file_f_path(file: *mut file) -> *mut path;
}
extern "C" {
    pub fn shim_file_f_path_user(file: *mut file) -> *mut path;
}
extern "C" {
    pub fn shim_file_f_path_exists(file: *mut file) -> bool;
}
extern "C" {
    pub fn shim_file_f_inode(file: *mut file) -> *mut inode;
}
extern "C" {
    pub fn shim_file_f_inode_user(file: *mut file) -> *mut inode;
}
extern "C" {
    pub fn shim_file_f_inode_exists(file: *mut file) -> bool;
}
extern "C" {
    pub fn shim_file_private_data(file: *mut file) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_file_private_data_user(file: *mut file) -> *mut ::core::ffi::c_void;
}
extern "C" {
    pub fn shim_file_private_data_exists(file: *mut file) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fdtable {
    pub max_fds: ::core::ffi::c_uint,
    pub fd: *mut *mut file,
}
extern "C" {
    pub fn shim_fdtable_max_fds(fdtable: *mut fdtable) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_fdtable_max_fds_user(fdtable: *mut fdtable) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_fdtable_max_fds_exists(fdtable: *mut fdtable) -> bool;
}
extern "C" {
    pub fn shim_fdtable_fd(fdtable: *mut fdtable) -> *mut *mut file;
}
extern "C" {
    pub fn shim_fdtable_fd_user(fdtable: *mut fdtable) -> *mut *mut file;
}
extern "C" {
    pub fn shim_fdtable_fd_exists(fdtable: *mut fdtable) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct files_struct {
    pub fdt: *mut fdtable,
    pub fd_array: [*mut file; 1usize],
}
extern "C" {
    pub fn shim_files_struct_fdt(files_struct: *mut files_struct) -> *mut fdtable;
}
extern "C" {
    pub fn shim_files_struct_fdt_user(files_struct: *mut files_struct) -> *mut fdtable;
}
extern "C" {
    pub fn shim_files_struct_fdt_exists(files_struct: *mut files_struct) -> bool;
}
extern "C" {
    pub fn shim_files_struct_fd_array(files_struct: *mut files_struct) -> *mut [*mut file; 1usize];
}
extern "C" {
    pub fn shim_files_struct_fd_array_user(
        files_struct: *mut files_struct,
    ) -> *mut [*mut file; 1usize];
}
extern "C" {
    pub fn shim_files_struct_fd_array_exists(files_struct: *mut files_struct) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct task_struct {
    pub files: *mut files_struct,
}
extern "C" {
    pub fn shim_task_struct_files(task_struct: *mut task_struct) -> *mut files_struct;
}
extern "C" {
    pub fn shim_task_struct_files_user(task_struct: *mut task_struct) -> *mut files_struct;
}
extern "C" {
    pub fn shim_task_struct_files_exists(task_struct: *mut task_struct) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ucred {
    pub pid: __u32,
    pub uid: __u32,
    pub gid: __u32,
}
extern "C" {
    pub fn shim_ucred_pid(ucred: *mut ucred) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_ucred_pid_user(ucred: *mut ucred) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_ucred_pid_exists(ucred: *mut ucred) -> bool;
}
extern "C" {
    pub fn shim_ucred_uid(ucred: *mut ucred) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_ucred_uid_user(ucred: *mut ucred) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_ucred_uid_exists(ucred: *mut ucred) -> bool;
}
extern "C" {
    pub fn shim_ucred_gid(ucred: *mut ucred) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_ucred_gid_user(ucred: *mut ucred) -> ::core::ffi::c_uint;
}
extern "C" {
    pub fn shim_ucred_gid_exists(ucred: *mut ucred) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bio_vec {
    pub _address: u8,
}
