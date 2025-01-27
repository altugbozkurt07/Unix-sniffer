use aya_ebpf::{cty::c_void, helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel, gen::bpf_probe_read_kernel_str}, macros::{kprobe, kretprobe}, programs::{ProbeContext, RetProbeContext}};
use aya_log_ebpf::info;
use unix_sniffer_common::{events::{ScmPassedFdEvent, Ucred, UnixEvent, MAX_FD_ENTRY, SCM_CREDENTIALS, SCM_MAX_FD, SCM_RIGHTS}, utils::{bound_value_for_verifier, cap_size}};
use unix_sniffer_common::co_re::{self, Core};
use unix_sniffer_common::alloc;

use crate::{EVENTS, SCMEVENTS, UCREDEVENTS};

pub const SOL_SOCKET: i32 = 1;

#[kprobe]
pub fn track_scm_send(ctx: ProbeContext) -> u32 {
    match try_track_scm_send(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
pub fn try_track_scm_send(ctx: ProbeContext) -> Result<u32, u32> {
    let msghdr_core = co_re::msghdr::from_ptr(ctx.arg(1).ok_or(1u32)?);

    alloc::init()?;
    let fd_event = alloc::alloc_zero::<UnixEvent>()?;

    unsafe{
        
        let msg_controllen = msghdr_core.msg_controllen().ok_or(1u32)?;
        let cmsg_len = core::mem::size_of::<co_re::gen::cmsghdr>();

        if msg_controllen as usize >= cmsg_len {
            //info!(&ctx,"msg_controllen : {}", cmsg_len);

            let mut cmsg_blobs = co_re::cmsghdr::cmsg_firsthdr(msghdr_core);

            for i in 0..20{

                if cmsg_blobs.is_null(){
                    //info!(&ctx, "cmsg_blob is null");
                    return Err(1u32);
                }

                if !cmsg_blobs.cmsg_ok(msghdr_core){
                    info!(&ctx, "cmsg_blob is not eligible");
                    return Err(1u32);
                }

                let cmsg_level = cmsg_blobs.cmsg_level().ok_or(1u32)?;
                if cmsg_level != SOL_SOCKET{
                    info!(&ctx, "cmsg_blob is not SOL_SOCKET");
                    continue
                }
                
                let cmsg_type = cmsg_blobs.cmsg_type().ok_or(1u32)?;
                match cmsg_type{
                    SCM_RIGHTS => {
                        if let Some(num) = cmsg_blobs.num(){
                            let fd_event = alloc::alloc_zero::<ScmPassedFdEvent>()?;

                            if num as usize > SCM_MAX_FD{
                                info!(&ctx, "cmsg_blob num is overflowed");
                                return Err(1u32);
                            }
    
                            let cmsg_data = cmsg_blobs.cmsg_data();
                            if cmsg_data.is_none(){
                                info!(&ctx, "data is null");
                                return Err(1u32);
                            }
                            
                            let data = cmsg_data.ok_or(1u32)?;
                            
                            let verified_num = bound_value_for_verifier(num as isize, 0, 100 as isize);
                                
                            if let Err(_) = fd_event.parse_fd_scm(data, num as i32){
                                return Err(1u32);
                            }
    
                            fd_event.comm = bpf_get_current_comm().map_err(|e| {
                                info!(&ctx, "failed to read comm");
                                e as u32
                            })?;
                            fd_event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
                
                            SCMEVENTS.output(&ctx, &fd_event, 0);
                        }
                    },
                    SCM_CREDENTIALS => {
                        let cmsg_size = cmsg_blobs.cmsg_len().ok_or(1u32)?;
                        let cmsg_hdr = cmsg_blobs.cmsg_hdr_len(core::mem::size_of::<co_re::gen::ucred>());
                        if cmsg_size as usize != cmsg_hdr{
                            info!(&ctx, "cmgs_size: {} -- cmsg_hdr_len: {}", cmsg_size, cmsg_hdr);
                            return Err(1u32);
                        }
                        let cmsg_data = cmsg_blobs.cmsg_data();
                        if cmsg_data.is_none(){
                            info!(&ctx, "data is null");
                            return Err(1u32);
                        }
                        let data = cmsg_data.ok_or(1u32)?;
                        let ucred = co_re::ucred::from_ptr(data as *const co_re::gen::ucred);
                       
                        let ucred_event = alloc::alloc_zero::<Ucred>()?;
                        ucred_event.sending_pid = ucred.pid().ok_or(1u32)?;
                        ucred_event.sending_uid = ucred.uid().ok_or(1u32)?;
                        ucred_event.sending_gid = ucred.gid().ok_or(1u32)?;

                        ucred_event.comm = bpf_get_current_comm().map_err(|e| {
                            info!(&ctx, "failed to read comm");
                            e as u32
                        })?;
                        
                        UCREDEVENTS.output(&ctx, &ucred_event, 0);
                        
                    },
                    _ => {}
                    
                
                }

                cmsg_blobs = cmsg_blobs.cmsg_get_next_hdr(msghdr_core);
            }
            

       }
    }

    Ok(0)
}

