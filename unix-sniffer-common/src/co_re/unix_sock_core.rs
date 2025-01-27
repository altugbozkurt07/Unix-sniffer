use core::ffi::c_void;
use core::ffi::c_char;
use crate::utils::bound_value_for_verifier;
use crate::kernel;
use crate::version::kernel_version;

use super::{Core,rust_shim_kernel_impl};
use super::gen::{self, *};

use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};

#[allow(non_camel_case_types)]
pub type sockaddr_un = Core<gen::sockaddr_un>;

impl sockaddr_un{
    rust_shim_kernel_impl!(pub, sockaddr_un, sun_path, *mut c_char);
} 


#[allow(non_camel_case_types)]
pub type unix_address = Core<gen::unix_address>;

impl unix_address{
    rust_shim_kernel_impl!(pub, unix_address, len, i32);
    rust_shim_kernel_impl!(pub, unix_address, name, sockaddr_un);
}

#[allow(non_camel_case_types)]
pub type inode = Core<gen::inode>;

impl inode{
    rust_shim_kernel_impl!(pub, inode, i_ino, u64);
}

#[allow(non_camel_case_types)]
pub type dentry = Core<gen::dentry>;

impl dentry{
    rust_shim_kernel_impl!(pub, dentry, d_inode, inode);
}

#[allow(non_camel_case_types)]
pub type path = Core<gen::path>;

impl path{
    rust_shim_kernel_impl!(pub, path, dentry, dentry);
}

#[allow(non_camel_case_types)]
pub type unix_sock = Core<gen::unix_sock>;

impl unix_sock{
    rust_shim_kernel_impl!(pub, unix_sock, peer, sock);
    rust_shim_kernel_impl!(pub, unix_sock, addr, unix_address);
    rust_shim_kernel_impl!(pub, unix_sock, path, path);
}

#[allow(non_camel_case_types)]
pub type sock_common = Core<gen::sock_common>;

impl sock_common{
    rust_shim_kernel_impl!(pub, sock_common, skc_family, u16);
}

#[allow(non_camel_case_types)]
pub type upid = Core<gen::upid>;

impl upid{
    rust_shim_kernel_impl!(pub, upid, nr, i32);
}

#[allow(non_camel_case_types)]
pub type pid = Core<gen::pid>;

impl pid{
    rust_shim_kernel_impl!(pub, pid, numbers, upid);
}


#[allow(non_camel_case_types)]
pub type sock = Core<gen::sock>;


impl From<sock> for unix_sock {
    #[inline(always)]
    fn from(value: sock) -> Self {
        Self::from_ptr(value.as_ptr() as *const _)
    }
}

impl sock{
    rust_shim_kernel_impl!(pub, sock, __sk_common, sock_common);
    rust_shim_kernel_impl!(pub, sock, sk_peer_pid, pid);
}

#[allow(non_camel_case_types)]
pub type socket = Core<gen::socket>;

impl socket{
    rust_shim_kernel_impl!(pub, socket, sk, sock);
}

#[repr(C)]
#[derive(PartialEq)]
#[allow(non_camel_case_types)]
/// IterType encodes the iter type. We cannot use the enum defined
/// in the Linux Kernel as it is not stable accross versions.
pub enum IterType {
    ITER_IOVEC,
    ITER_KVEC,
    ITER_BVEC,
    ITER_XARRAY,
    ITER_PIPE,
    ITER_DISCARD,
    ITER_UBUF,
}

impl IterType {
    fn from_u8(iter_type: u8) -> Option<Self> {
        let kernel = kernel_version();
        let t = {
            if kernel < kernel!(5, 14, 0) {
                (iter_type & 0b11111100) as u32
            } else {
                iter_type as u32
            }
        };

        unsafe {
            match t {
                x if shim_iter_type_ITER_IOVEC_exists() && x == shim_iter_type_ITER_IOVEC() => {
                    Some(IterType::ITER_IOVEC)
                }
                x if shim_iter_type_ITER_KVEC_exists() && x == shim_iter_type_ITER_KVEC() => {
                    Some(IterType::ITER_KVEC)
                }
                x if shim_iter_type_ITER_BVEC_exists() && x == shim_iter_type_ITER_BVEC() => {
                    Some(IterType::ITER_BVEC)
                }
                x if shim_iter_type_ITER_XARRAY_exists() && x == shim_iter_type_ITER_XARRAY() => {
                    Some(IterType::ITER_XARRAY)
                }
                x if shim_iter_type_ITER_PIPE_exists() && x == shim_iter_type_ITER_PIPE() => {
                    Some(IterType::ITER_PIPE)
                }
                x if shim_iter_type_ITER_DISCARD_exists() && x == shim_iter_type_ITER_DISCARD() => {
                    Some(IterType::ITER_DISCARD)
                }
                x if shim_iter_type_ITER_UBUF_exists() && x == shim_iter_type_ITER_UBUF() => {
                    Some(IterType::ITER_UBUF)
                }
                _ => None,
            }
        }
    }
}

#[allow(non_camel_case_types)]
pub type iov_iter = Core<gen::iov_iter>;


impl iov_iter{
    rust_shim_kernel_impl!(pub(self), _iov, iov_iter, iov, iovec);
    rust_shim_kernel_impl!(pub(self), ___iov, iov_iter, __iov, iovec);
    rust_shim_kernel_impl!(pub, iov_iter, nr_segs, u64);
    rust_shim_kernel_impl!(pub, iov_iter, ubuf, *mut c_void);
    rust_shim_kernel_impl!(pub(self), _iter_type, iov_iter, iter_type, u8);
    rust_shim_kernel_impl!(pub(self), _type, iov_iter, type, u32);
    rust_shim_kernel_impl!(pub, iov_iter, count, u64);

    pub unsafe fn get_iov(&self) -> Option<iovec>{
        self._iov().or(self.___iov())
    }

    #[inline(always)]
    pub unsafe fn iter_type(&self) -> Option<IterType> {
        let t = self._iter_type().or(self._type().map(|t| t as u8))?;

        IterType::from_u8(t)
    }

    fn is_iter_type(&self, ty: IterType) -> bool {
        if let Some(t) = unsafe { self.iter_type() } {
            return t == ty;
        }
        false
    }

    #[inline(always)]
    pub fn is_iter_iovec(&self) -> bool {
        self.is_iter_type(IterType::ITER_IOVEC)
    }

    #[inline(always)]
    pub fn is_iter_kvec(&self) -> bool {
        self.is_iter_type(IterType::ITER_KVEC)
    }

    #[inline(always)]
    pub fn is_iter_bvec(&self) -> bool {
        self.is_iter_type(IterType::ITER_BVEC)
    }

    #[inline(always)]
    pub fn is_iter_xarray(&self) -> bool {
        self.is_iter_type(IterType::ITER_XARRAY)
    }

    #[inline(always)]
    pub fn is_iter_discard(&self) -> bool {
        self.is_iter_type(IterType::ITER_DISCARD)
    }

    #[inline(always)]
    pub fn is_iter_ubuf(&self) -> bool {
        self.is_iter_type(IterType::ITER_UBUF)
    }

    #[inline(always)]
    pub unsafe fn iov(&self) -> Option<iovec> {
        self._iov().or(self.___iov())
    }
   
}



#[allow(non_camel_case_types)]
pub type iovec = Core<gen::iovec>;

impl iovec{
    rust_shim_kernel_impl!(pub, iovec, iov_base, *mut c_void);
    rust_shim_kernel_impl!(pub, iovec, iov_len, u64);
    
    #[inline(always)]
    pub unsafe fn add(&self, i: usize) -> Self{
        self.as_ptr().add(i).into()
    }
}

#[allow(non_camel_case_types)]
pub type msghdr = Core<gen::msghdr>;

impl msghdr{
    rust_shim_kernel_impl!(pub, msghdr, msg_iter, iov_iter);
    rust_shim_kernel_impl!(pub, msghdr, msg_controllen, u64);
    rust_shim_kernel_impl!(pub, msghdr, msg_control, *mut c_void);

    #[inline(always)]
    pub unsafe fn is_cmsg(&self) -> Result<bool, u32>{
        let cmsg_size = core::mem::size_of::<gen::cmsghdr>();
        let msg_controllen = self.msg_controllen().ok_or(1u32)?;
        if msg_controllen as usize >= cmsg_size{
            return Ok(true);
        }
        return Ok(false);
    }
}


#[allow(non_camel_case_types)]
pub type cmsghdr = Core<gen::cmsghdr>;

impl cmsghdr{
    rust_shim_kernel_impl!(pub, cmsghdr, cmsg_len, u64);
    rust_shim_kernel_impl!(pub, cmsghdr, cmsg_type, i32);
    rust_shim_kernel_impl!(pub, cmsghdr, cmsg_level, i32);

    #[inline(always)]
    pub unsafe fn cmsg_align(&self, len: usize) -> usize {
        (len + ::core::mem::size_of::<usize>() - 1) & !(::core::mem::size_of::<usize>() - 1)
    }

    #[inline(always)]
    pub unsafe fn cmsg_get_next_hdr(&self, msg_hdr: Core<gen::msghdr>) -> Self{

        if let Some(len) = self.cmsg_len(){
            let verified_len = bound_value_for_verifier(len as isize, 0, 100);
            let verified_cmsghdr_len = bound_value_for_verifier(::core::mem::size_of::<gen::cmsghdr>() as isize, 0, 100);
            if (verified_len as usize) < verified_cmsghdr_len as usize {
                return (0 as *mut gen::cmsghdr).into()
            }

            let next = cmsghdr::from_ptr((self.as_ptr() as usize + self.cmsg_align(verified_len as usize)) as *mut gen::cmsghdr);

            if let Some(msg_control) = msg_hdr.msg_control(){
                if let Some(msg_len) = msg_hdr.msg_controllen(){
                    let verified_msg_len = bound_value_for_verifier(msg_len as isize, 0, 100);
                    let max = msg_control as usize + verified_msg_len as usize;
                    let verified_max = bound_value_for_verifier(max as isize, 0, 100);
                    if let Some(next_len) = next.cmsg_len(){
                        let verified_next_len = bound_value_for_verifier(next_len as isize, 0, 100);
                        if next.as_ptr().offset(1) as usize - msg_control as usize > verified_msg_len as usize{
                            return (0 as *mut gen::cmsghdr).into();
                        }else {
                            return next;
                        }
                    }
                }   
                    
            }
               
        }

        
        return (0 as *mut gen::cmsghdr).into();

    }

    #[inline(always)]
    pub unsafe fn num(&self) -> Option<u64> {
        let cmsg_len = self.cmsg_len()?;
        Some(cmsg_len - (core::mem::size_of::<gen::cmsghdr>() as u64) / (core::mem::size_of::<i32>() as u64))
    }

    #[inline(always)]
    pub unsafe fn add(&self, i: usize) -> Self{
        self.as_ptr().add(i).into()
    }

    #[inline(always)]
    pub unsafe fn cmsg_hdr_len(&self, len: usize) -> usize{
        self.cmsg_align(::core::mem::size_of::<gen::cmsghdr>()) as usize + len
    }

    #[inline(always)]
    pub unsafe fn cmsg_data(&self) -> Option<*mut u8>{
        Some(self.as_ptr().offset(1) as *mut u8)
    }

    #[inline(always)]
    pub unsafe fn cmsg_firsthdr(msg_hdr: Core<gen::msghdr>) -> Self{
        if let Some(msg_controllen) = msg_hdr.msg_controllen(){
            let verified_msg_controllen = bound_value_for_verifier(msg_controllen as isize, 0, 100);
            let verified_cmsghdr_len = bound_value_for_verifier(::core::mem::size_of::<gen::cmsghdr>() as isize, 0, 100);
            if verified_msg_controllen as usize >= verified_cmsghdr_len as usize{
                if let Some(cmsg) = msg_hdr.msg_control(){
                    return (cmsg as *mut gen::cmsghdr).into();
                }
            }
        }
        return (0 as *mut gen::cmsghdr).into();
    }

    pub unsafe fn cmsg_ok(&self, msg_hdr: Core<gen::msghdr>) -> bool{
        if let Some(len) = self.cmsg_len(){
            if let Some(control_len) = msg_hdr.msg_controllen(){
                if let Some(msg_ctr) = msg_hdr.msg_control(){
                    return ((len as usize >= ::core::mem::size_of::<gen::cmsghdr>() as usize) && (len as usize <= (control_len as usize - (self.as_ptr() as usize) - msg_ctr as usize))) as bool;
                }
            }
        }
        false
     }
} 


#[allow(non_camel_case_types)]
pub type fdtable = Core<gen::fdtable>;

impl fdtable{
    rust_shim_kernel_impl!(pub, fdtable, max_fds, u32);
    rust_shim_kernel_impl!(pub, fdtable, fd, *mut *mut gen::file);
}

#[allow(non_camel_case_types)]
pub type files_struct = Core<gen::files_struct>;

impl files_struct{
    rust_shim_kernel_impl!(pub, files_struct, fdt, fdtable);

    pub unsafe fn get_file(&self, fd: usize) -> bool{
        if let Some(fdtable) = self.fdt(){
            if let Some(max_fds) = fdtable.max_fds(){
                if fd <= max_fds as usize{
                    if let Some(fd_array) = fdtable.fd(){
                        if let Ok(_) = bpf_probe_read_kernel(fd_array.add(fd)){
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}


#[allow(non_camel_case_types)]
pub type task_struct = Core<gen::task_struct>;

impl task_struct{
    rust_shim_kernel_impl!(pub, task_struct, files, files_struct);

    #[inline(always)]
    pub unsafe fn current() -> Self{
        Self::from_ptr(bpf_get_current_task() as *const _)
    }

    #[inline(always)]
    pub unsafe fn check_fd(&self, fd: usize) -> bool{
        if let Some(files) = self.files(){
            return files.get_file(fd);
        }

        return false;
    }

}

#[allow(non_camel_case_types)]
pub type ucred = Core<gen::ucred>;

impl ucred{
    rust_shim_kernel_impl!(pub, ucred, pid, u32);
    rust_shim_kernel_impl!(pub, ucred, uid, u32);
    rust_shim_kernel_impl!(pub, ucred, gid, u32);
}