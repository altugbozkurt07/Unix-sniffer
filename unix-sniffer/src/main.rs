use aya::programs::KProbe;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn, debug};
use structopt::StructOpt;
use tokio::signal;
use unix_sniffer_common::events::{ScmPassedFdEvent, Ucred, UnixEvent};
mod watcher;
use aya::{
    maps::AsyncPerfEventArray,
    util::online_cpus,
};
use bytes::BytesMut;
use crate::watcher::SystemWatcher;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/unix-sniffer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/unix-sniffer"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("unix_stream_sendmsg").unwrap().try_into()?;
    program.load()?;
    program.attach("unix_stream_sendmsg", 0)?;

    let scm_tracker_program: &mut KProbe = bpf.program_mut("track_scm_send").unwrap().try_into()?;
    scm_tracker_program.load()?;
    scm_tracker_program.attach("__scm_send", 0)?;

    let mut sys = SystemWatcher::new(&mut bpf)?;
    sys.load_socket_filter(std::env::args().nth(1));

    let args = Cli::from_args();
    let cpus = online_cpus().map_err(|_| anyhow::Error::msg("could not get cpu count"))?;
    let num_cpus = cpus.len();
    
    match args.command {
        Command::UnixSocket => {
            listen_unix_socket_events(cpus.clone(), num_cpus.clone(), &mut bpf).await?;
        }
        Command::ScmFds => {
            listen_scm_fd_events(cpus.clone(), num_cpus.clone(), &mut bpf).await?;
        }
        Command::ScmCreds => {
            listen_scm_credentials_events(cpus.clone(), num_cpus.clone(), &mut bpf).await?;
        }
    }
    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

pub async fn listen_unix_socket_events<'a>(cpus: Vec<u32>, num_cpus: usize, bpf: &'a mut Ebpf) -> Result<(), anyhow::Error>{
    println!("UNIX SOCKET EVENT LISTENER WILL BE STARTED");
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("UNIXEVENT").expect("could not take map"))?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                match buf.read_events(&mut buffers).await{
                    Ok(events) => {
                        for i in 0..events.read {
              
                            let buf = &mut buffers[i];
                            let ptr = buf.as_ptr() as *const UnixEvent;
                           
                            let mut data = unsafe { ptr.read_unaligned() };
                            let comm = String::from_utf8_lossy(&data.comm).to_string();
                            let mut bytes = data.data.as_slice();
                            println!("DATA len: {}", data.data.len());
                            let message = String::from_utf8_lossy(&bytes).to_string();
                            let local_path = String::from_utf8_lossy(&data.local_path.as_slice()).to_string().trim_matches(char::from(0)).to_string();
                            let peer_path = String::from_utf8_lossy(&data.peer_path.as_slice()).to_string().trim_matches(char::from(0)).to_string();
                    
                            println!("NEW EVENT:\n data: {:?}\n local_path: {:?}\n peer path: {:?}\n peer pid: {:?}\n pid: {:?}\n unix_socket_inode {:?}\n", message, local_path, peer_path, data.peer_pid.clone(), data.pid.clone(), data.unix_inode_n.clone());

                        }
        
                        println!("NEW EVENT -- ")
        
                    },
                    Err(e) => {
                        println!("error when receiving events: {:?}", e)
                    }
                }
            }
        });
    }

    Ok(())

}

pub async fn listen_scm_fd_events<'a>(cpus: Vec<u32>, num_cpus: usize, bpf: &'a mut Ebpf) -> Result<(), anyhow::Error> {
    println!("SCM FDS EVENT LISTENER WILL BE STARTED");
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("SCMEVENTS").expect("could not take map"))?;
    println!("FDS PASSED TO A DIFFERENT PROCESS -- ");

    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                match buf.read_events(&mut buffers).await{
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &mut buffers[i];
                            let ptr = buf.as_ptr() as *const ScmPassedFdEvent;
                            let data = unsafe { ptr.read_unaligned() };
                            
                            let mut fd_bytes = data.fds.as_slice().to_owned();
                            let fd_data_ptr: *const i32 = fd_bytes.as_mut_ptr() as *const i32;
                            let comm = String::from_utf8_lossy(&data.comm).to_string();
                            for pos in 0..data.fds.len / core::mem::size_of::<i32>(){
                                let fd = unsafe { *fd_data_ptr.offset(pos as _) };
                                if fd != 0 {
                                    //println!("new fd: {}", fd);
                                    let path = format!("/proc/{}/fd/{}", data.pid, fd);
                                    match std::fs::read_link(&path) {
                                        Err(_) => {
                                            println!("ACTION=SEND -- Comm: {} -- Pid: {} -- new fd: {} - symlink : <Not-available>", comm, data.pid.clone(), fd);
                                        },//probably the process that owns the fd exited so process metadata in procfs is already destroyed
                                        Ok(file) => {
                                            println!("ACTION=SEND -- Comm: {} -- Pid: {} -- new fd: {} - symlink : {:?}", comm, data.pid.clone(), fd, file.into_os_string());
                                        },
                                    };
                                }
                            }
                        }
        
                    },
                    Err(e) => {
                        println!("error when receiving events: {:?}", e)
                    }
                }
            }
        });
    }

    Ok(())
}


pub async fn listen_scm_credentials_events<'a>(cpus: Vec<u32>, num_cpus: usize, bpf: &'a mut Ebpf) -> Result<(), anyhow::Error> {
    println!("SCM CREDENTIAL EVENT LISTENER WILL BE STARTED");
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("UCREDEVENTS").expect("could not take map"))?;

    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                match buf.read_events(&mut buffers).await{
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &mut buffers[i];
                            let ptr = buf.as_ptr() as *const Ucred;
                            let data = unsafe { ptr.read_unaligned() };
                            let comm = String::from_utf8_lossy(&data.comm).to_string();
                            println!("NEW SCM_CREDENTIAL EVENT: sending_pid: {} -- sending_uid: {} -- sending_gid: {} -- comm: {}", data.sending_pid, data.sending_uid, data.sending_gid, comm)
                           
                        }
        
                    },
                    Err(e) => {
                        println!("error when receiving events: {:?}", e)
                    }
                }
            }
        });
    }

    Ok(())
}


#[derive(Debug, StructOpt)]
#[structopt(name = "unixsniffer", about = "Sniff unix socket data and scm events")]
struct Cli {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt, Debug)]
enum Command {
    /// Handle Unix socket operations
    UnixSocket,
    /// Handle SCM file descriptors
    ScmFds,
    /// Handle SCM credentials
    ScmCreds,
}
