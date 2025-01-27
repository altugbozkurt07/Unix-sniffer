use super::Buffer;

use aya_ebpf::check_bounds_signed;
use aya_ebpf::helpers::gen::{bpf_probe_read_kernel_str, bpf_probe_read_user, bpf_probe_read_user_str};
use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::co_re::{iovec as iovec_core, task_struct};
use crate::utils::{bound_value_for_verifier, cap_size};
use core::cmp::min;

const SCM_RIGHTS_COUNT: u16 = 10;

impl<const N: usize> Buffer<N> {
    #[inline(always)]
    pub unsafe fn append_iov_core(&mut self, iov: iovec_core) -> Result<u32, u32> {

        let iov_len = iov.iov_len().ok_or(1u32)?;

        let iov_base = iov.iov_base().ok_or(1u32)?;
        
        let len = cap_size(self.len, N);

        let size = min(iov_len as u32, N as u32);

        let left = cap_size((N - len) as u32, N as u32);

        if size > left {
            return Ok(0) 
        }

        if bpf_probe_read_user_str(
            self.buf[len as usize..N].as_mut_ptr() as *mut _,
            cap_size(size, N as u32),
            iov_base as *const _,
        ) < 0 {
            return Err(1u32);
        }

        self.len += size as usize;

        Ok(0)

    }

    #[inline(always)]
    pub unsafe fn append_fds(&mut self, fd_data: *mut u8, num: i32) -> Result<u32, u32>{

        let mut fd_int_ptr = fd_data as *mut i32;
        let verified_num = bound_value_for_verifier(num as isize, 0, 100 as isize);

        let current = task_struct::current();
        for i in 0..verified_num {
            
            if fd_int_ptr.is_null(){
                 self.iteration_count = i as usize;
                 return Ok(0)
            }

            let len = cap_size(self.len, N);

            let size = core::mem::size_of::<i32>();
            let verified_size = bound_value_for_verifier(size as isize, 0, 16);

            let size = min(verified_size as u32, N as u32);

            let left = cap_size((N - len) as u32, N as u32);

            if size  > left {
                self.iteration_count = i as usize;
                return Ok(0)
            }
            if let Ok(fd) = bpf_probe_read_kernel(fd_int_ptr){
                if current.check_fd(fd as usize){
                    if bpf_probe_read_kernel_str(self.buf[len as usize..N].as_mut_ptr() as *mut _, verified_size as u32, fd_int_ptr as *const _) < 0{
                        //self.iteration_count = i as usize;
                        self.fd_ptr = fd_int_ptr;
                        continue
                    }
                }
            }
            self.len += verified_size as usize;

            fd_int_ptr = fd_int_ptr.offset(i + 1 as isize);

            self.iteration_count = i as usize;
             
        }

         Ok(0)
    }

    #[inline(always)]
    pub unsafe fn read_user_at<P>(&mut self, from: *const P, size: u32) -> Result<(), u32> {
        let size = (size as i64).clamp(0, N as i64);

        if check_bounds_signed(size as i64, 0, N as i64) {
            let ret = bpf_probe_read_user(
                self.buf.as_mut_ptr() as *mut _,
                size as u32,
                from as *const _,
            );
            if ret != 0 {
                return Err(1u32);
            }
        }

        self.len = size as usize;
        Ok(())
    }

}