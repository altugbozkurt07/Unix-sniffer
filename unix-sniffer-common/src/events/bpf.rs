
use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;

use crate::co_re::{self, cmsghdr, iov_iter as iov_iter_core, sock as sock_core, unix_address as unix_address_core, unix_sock as unix_sock_core, Core};

use super::{UnixError, UnixEvent, ScmPassedFdEvent};

pub const SCM_RIGHTS: i32 = 0x01;
pub const SCM_CREDENTIALS: i32 = 0x02;

impl UnixEvent{
#[inline(always)]
    pub unsafe fn parse_iov_iter_core<const MAX_NR_SEGS: usize>(
        &mut self,
        iter: iov_iter_core,
        nr_segs: usize,
    ) -> Result<u32, u32> {

        if iter.is_iter_ubuf(){
            let ubuf = iter.ubuf().ok_or(1u32)?;
            let count = iter.count().ok_or(1u32)?;

            self.data.read_user_at(ubuf, count as u32);
            
        } else if iter.is_iter_iovec() {
            let iov = iter.iov().ok_or(1u32)?;

            if iov.is_null() {
                return Err(1u32);
            }

            for i in 0..MAX_NR_SEGS {
                if self.data.is_full() || i >= nr_segs {
                    break;
                }
                self.data.append_iov_core(iov)?;

                iov.add(i);
            }
        } else {
            return Err(1u32);
        }

        Ok(0)

        // let iov = iter.get_iov().ok_or(1u32)?;
        // if iov.is_null(){
        //     return Ok(0)               
        // }

        // for i in 0..MAX_NR_SEGS {

        //     if self.data.is_full() || i >= nr_segs{
        //        break;
        //     }

        //     self.data.append_iov_core(iov)?;

        //     iov.add(i);
                
        // }

    }

    pub unsafe fn parse_socket_paths_core(
        &mut self,
        sock: sock_core,
    ) -> Result<u32, UnixError> {
        
        let local: Core<co_re::gen::unix_sock> = sock.into();
    
        let peer_core_sock = local.peer().ok_or(UnixError::FieldParseError)?;
        let peer_core = co_re::unix_sock::from_ptr(peer_core_sock.as_ptr() as * const co_re::gen::unix_sock);
        
        match self.parse_sunpath_core(local, false){
            Ok(_) => {return Ok(0);},
            Err(UnixError::UnixAddressEmpty) => {
                match self.parse_sunpath_core(peer_core, true){
                    Ok(_) => {return Ok(0)},
                    Err(e) => {return Err(e);}
                }
            },
            Err(e) => {return Err(e);},
        }

    }

    pub unsafe fn parse_sunpath_core(
        &mut self,
        unix_sock: unix_sock_core,
        is_peer: bool,
    ) -> Result<u32,UnixError> {

        let unix_address_core = unix_sock.addr().ok_or(UnixError::FieldParseError)?;

        if unix_address_core.is_null(){
            return Err(UnixError::UnixAddressEmpty);
        }

        let unix_len_core = unix_address_core.len().ok_or(UnixError::FieldParseError)?;

        if unix_len_core as u32 > 0{
            
            if let Ok(inode_n) = self.parse_inode_n_core(unix_sock){
                self.unix_inode_n = inode_n;
            }


            let sockaddr_core = unix_address_core.name().ok_or( UnixError::FieldParseError)?;
            let sunpath_core = sockaddr_core.sun_path().ok_or( UnixError::FieldParseError)?;

            if is_peer{
                bpf_probe_read_kernel_str_bytes(
                    sunpath_core as *const u8,
                    &mut self.peer_path,
                ).map_err(|_| UnixError::FieldParseError)?;
                self.peer_path_len += unix_len_core as u32;

            }else  {
                bpf_probe_read_kernel_str_bytes(
                    sunpath_core as *const u8,
                    &mut self.local_path,
                ).map_err(|_| UnixError::FieldParseError)?;

                self.local_path_len += unix_len_core as u32;
            }

        }

    Ok(0)
    }

    pub unsafe fn parse_inode_n_core(
        &self,
        unix_sock: unix_sock_core,
    ) -> Result<u64, UnixError> {

        let path_core = unix_sock.path().ok_or(UnixError::FieldParseError)?;

        let dentry_core = path_core.dentry().ok_or(UnixError::FieldParseError)?;

        let inode_core = dentry_core.d_inode().ok_or(UnixError::FieldParseError)?;

        let inode_n_core = inode_core.i_ino().ok_or(UnixError::FieldParseError)?;
        
        Ok(inode_n_core)
    }

}


impl ScmPassedFdEvent{
    pub unsafe fn parse_fd_scm(&mut self, data: *mut u8, num: i32) -> Result<u64, UnixError>{
        if let Err(_) = self.fds.append_fds(data, num){
            return Err(UnixError::CmsgBufferParse)
        }

        Ok(0)
    }
}