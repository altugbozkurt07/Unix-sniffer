
use aya::{maps::{HashMap as AyaHashMap, MapData}, Bpf, Ebpf};



use std::{ io, os::unix::fs::MetadataExt, path::Path};

use tracing::{debug, error};

pub struct SystemWatcher{
    tracked_files:  AyaHashMap<MapData, u64, i32>,
}

//new(bpf: &mut Bpf)
impl SystemWatcher{
    pub fn new(bpf: &mut Ebpf ) -> Result<Self, io::Error> {
        let tracked_files: AyaHashMap<_, u64, i32> = AyaHashMap::try_from(bpf.take_map("TRACKED_INODE_N").unwrap()).unwrap();

        Ok(SystemWatcher {
            tracked_files,
        })
    }

    pub fn load_socket_filter(&mut self, user_supplied: Option<String>) {

        let mut socket_path: Vec<String> = vec![];

        if let Some(file_path) = user_supplied{
            println!("user supplied arg passed");
            let path = file_path.to_owned();
            socket_path.push(path);
        }else{
            println!("default values initialized");
            socket_path.push("/var/run/docker.sock".to_string());
            socket_path.push("/tmp/konfik.sock".to_string());
        }
        
        for service_path in socket_path{
            debug!(path = service_path, "checking socket path");
            let p = Path::new(&service_path);
            if p.exists() {
                let metadata = p.metadata().unwrap();
                let ino = metadata.ino();
                if let Some(path_name) = p.file_name(){
                    println!("ino number: {} : {}", ino,path_name.to_string_lossy());
                }
                self.tracked_files.insert(ino, 0, 0).expect("could not load inode number in map");
            }
        }

        println!("socket filters are added")

    }
}