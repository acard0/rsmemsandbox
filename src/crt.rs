use windows::core::s;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::Foundation::{CloseHandle, HMODULE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_READWRITE};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};
use std::ffi::CString;
use std::path::Path;

use crate::misc::query_hmodule;

pub(super) fn crt_load_library_int(pid: u32, sz_path: &str) -> Result<HMODULE, Box<dyn std::error::Error>> {
    let sz_hmodule = Path::new(sz_path).file_name().unwrap().to_str().unwrap();
    let m_hmodule_path = CString::new(sz_path.to_string()).unwrap();

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        let r_mem = VirtualAllocEx(
            process,
            None,
            m_hmodule_path.to_bytes_with_nul().len(),
            MEM_COMMIT,
            PAGE_READWRITE,
        );
        
        if r_mem.is_null() {
            return Err("Allocation failure".into());
        }

        WriteProcessMemory(process,r_mem,m_hmodule_path.as_ptr() as *const _,m_hmodule_path.to_bytes_with_nul().len(),None)?;

        let hkernel32 = GetModuleHandleA(s!("kernel32"))?;
        let loadlibraryaproc = GetProcAddress(hkernel32, s!("LoadLibraryA")).unwrap();
        let thread = CreateRemoteThread(process,None,0,Some(std::mem::transmute(loadlibraryaproc)),Some(r_mem as *mut _),0,None)?;

        CloseHandle(thread)?;

        let hmod = match query_hmodule(process, sz_hmodule) {
            Some(hmod) => {
                Ok(hmod)
            },
            None => {
                Err("Failed to locate the module".into())
            }
        };
        
        CloseHandle(process)?;
        hmod
    }
}