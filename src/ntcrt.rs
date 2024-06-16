use windows::core::s;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_READWRITE};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS};
use std::ffi::{c_void, CString};

use std::path::Path;
use std::ptr::null_mut;

use crate::misc::query_hmodule;

type NtCreateThreadExProc = unsafe extern "system" fn(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut u8,
    process_handle: HANDLE,
    start_address: *mut c_void,
    parameter: *mut c_void,
    create_suspended: u32,
    stack_zero_bits: u32,
    size_of_stack_commit: u32,
    size_of_stack_reserven: u32,
    bytes_buffer: *mut u8,
) -> u32;

pub(super) fn ntcrt_load_library_int(process: u32, sz_path: &str) -> Result<HMODULE, Box<dyn std::error::Error>> {
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, process)?;
    
        let sz_hmodule = Path::new(sz_path).file_name().unwrap().to_str().unwrap();
        let m_hmodule_path = CString::new(sz_path.to_string()).unwrap();
        let sz_hmodule_len = m_hmodule_path.as_bytes_with_nul().len();

        let params = VirtualAllocEx(
            process,
            None,
            sz_hmodule_len,
            MEM_COMMIT,
            PAGE_READWRITE,
        );

        if params.is_null() {
            return Err("Allocation failure".into());
        }

        WriteProcessMemory(
            process,
            params,
            m_hmodule_path.as_ptr() as *const _,
            sz_hmodule_len,
            None,
        )?;

        let kernel32 = GetModuleHandleA(s!("kernel32")).unwrap();
        let load_library_a = GetProcAddress(kernel32, s!("LoadLibraryA")).unwrap();

        let nt_create_thread_ex = get_nt_create_thread_ex()?;
        let mut thread_handle: HANDLE = HANDLE::default();
        let status = nt_create_thread_ex(&mut thread_handle, 0, null_mut(), process, load_library_a as *mut c_void, params, false.into(), 0, 0, 0, null_mut());

        if status == 0 {
            return Err(format!("NtCreateThreadEx failed. {:?}", GetLastError()).into());
        }

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

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

unsafe fn get_nt_create_thread_ex() -> Result<NtCreateThreadExProc, Box<dyn std::error::Error>> {
    let ntdll = LoadLibraryA(s!("ntdll")).unwrap();
    let nt_create_thread_ex = GetProcAddress(ntdll, s!("NtCreateThreadEx"));
    if nt_create_thread_ex.is_none() {
        return Err("NtCreateThreadEx procedure not found".into());
    }

    Ok(std::mem::transmute(nt_create_thread_ex.unwrap()))
}