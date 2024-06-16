#![allow(dead_code)]
#![allow(unused_variables)]

use mmap::mmap_load_library_int;
use sysinfo::System;

use std::path::Path;

mod mmap;
mod crt;
mod ntcrt;
mod swhex;
mod misc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hmodule = mmap_load_library_int(get_process_id_by_name("Notepad.exe").unwrap(), Path::new("dummypayload_hello.dll").to_str().unwrap())?;
    println!("Done. {:?}", hmodule);
    Ok(())
}

fn get_process_id_by_name(process_name: &str) -> Option<u32> {
    let mut system = System::new_all();
    system.refresh_all();

    for (pid, process) in system.processes() {
        if process.name() == process_name {
            return Some(pid.as_u32());
        }
    }

    None
}