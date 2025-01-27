#![no_std]
#![no_main]

use aya_ebpf::cty::c_void;
use aya_ebpf::helpers::gen::bpf_probe_read_kernel_str;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
use unix_sniffer_common::alloc;
use unix_sniffer_common::events::{self, UnixError, UnixEvent, MAX_FD_ENTRY};
use unix_sniffer_common::co_re::{self, Core};
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes};
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;
use crate::maps::*;

mod maps;
mod scm_fd_tracker;

const AF_INET: u16 = 2;
const AF_UNIX: u16 = 1;
const AF_INET6: u16 = 10;
const MAX_SEGS_PER_MSG: u32= 1024;
pub const SCM_RIGHTS: i32 = 0x01;
const SCM_RIGHTS_COUNT: usize = 10;
 
#[inline]
#[allow(unused_variables)]
pub fn bound_value_for_verifier(v: isize, min: isize, max: isize) -> isize {
    #[cfg(target_arch = "bpf")]
    {
        if v < min {
            return min;
        }
        if v > max {
            return max;
        }
    }
    v
}

#[kprobe]
pub fn unix_stream_sendmsg(ctx: ProbeContext) -> u32 {
    match try_unix_sniffer(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}



pub fn check_if_tracked(sock_path_id: u64) -> bool{
    unsafe{
        TRACKED_INODE_N.get(&sock_path_id).is_some()
    }
}



#[inline(always)]
fn try_unix_sniffer(ctx: ProbeContext) -> Result<u32, u32> {

    let socket_core = co_re::socket::from_ptr(ctx.arg(0).ok_or(1u32)?);

    alloc::init()?;
    let unix_event = alloc::alloc_zero::<UnixEvent>()?;
   
    unsafe {
        
        let sock_core = socket_core.sk().ok_or(1u32)?;

        let sock_common_core = sock_core.__sk_common().ok_or(1u32)?;
        let family_core = sock_common_core.skc_family().ok_or(1u32)?;

        let peer_pid_core = sock_core.sk_peer_pid().ok_or(1u32)?;

        if let Some(peer_upid_core) = peer_pid_core.numbers(){
            unix_event.peer_pid = peer_upid_core.nr().ok_or(1u32)? as u32;
        }
       

        match family_core {
            AF_UNIX => {
                
                match unix_event.parse_socket_paths_core(sock_core){
                    Ok(_) => {},
                    Err(UnixError::UnixAddressEmpty) => {return Err(1u32);}, //This means this is an abstract socket since both of local and peer unix_address are empty
                    Err(_) => {return Err(1u32);} //This means there was an error parsing some field from kernel structs with bpf helpers 
                }
                    

                if !check_if_tracked(unix_event.unix_inode_n.clone()){
                    return Err(1u32);
                }

                let msghdr_core = co_re::msghdr::from_ptr(ctx.arg(1).ok_or(1u32)?);
                let iov_iter_core = msghdr_core.msg_iter().ok_or(1u32)?;
                
                let nr_segs_core = iov_iter_core.nr_segs().ok_or(1u32)?;
                //info!(&ctx, "read iter_type core: {}", nr_segs_core);
                
                if let Err(_) = unix_event.parse_iov_iter_core::<128>(iov_iter_core, nr_segs_core as usize){
                    info!(&ctx, "error reading data");
                }
                    
                unix_event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;

                unix_event.comm = bpf_get_current_comm().map_err(|e| {
                    info!(&ctx, "failed to read comm");
                    e as u32
                })?;


                UNIXEVENT.output(&ctx, unix_event, 0);
            },
            _ => {
                return Ok(0);
            }
        }
    
     }

    Ok(0)

}



#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


