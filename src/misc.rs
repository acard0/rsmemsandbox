use std::{ffi::CString, mem::size_of};

use windows::Win32::{Foundation::{HANDLE, HMODULE}, System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW}};

#[repr(C)]
pub struct HResult {
    hmodule: HMODULE,
    lasterror: *mut i8
}

impl Into<HResult> for Result<HMODULE, Box<dyn std::error::Error>> {
    fn into(self) -> HResult {
        todo!()
    }
}

impl Drop for HResult {
    fn drop(&mut self) {
        _ = unsafe { CString::from_raw(self.lasterror) };
    }
}

pub fn query_hmodule(process: HANDLE, name: &str) -> Option<HMODULE> {
    unsafe {
        let mut hmods: [HMODULE; 1024] = [HMODULE(0); 1024];
        let mut cb_needed = 0;

        if EnumProcessModules(
            process,
            hmods.as_mut_ptr(),
            (size_of::<HMODULE>() * hmods.len()) as u32,
            &mut cb_needed,
        ).is_ok()
        {
            let num_modules = cb_needed / size_of::<HMODULE>() as u32;
            for i in 0..num_modules {
                let mut module_name = [0u16; 256];
                if GetModuleBaseNameW(
                    process,
                    hmods[i as usize],
                    &mut module_name
                ) > 0
                {
                    let sz_mod = String::from_utf16_lossy(&module_name);
                
                    if sz_mod.contains(name) {
                        return Some(hmods[i as usize]);
                    }
                }
            }
        }

        None
    }
}