#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::ffi::{c_void, CStr};
use std::mem::{size_of, transmute, zeroed};

use windows::core::{s, HRESULT, PCSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE, STILL_ACTIVE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_NT_HEADERS64, IMAGE_RUNTIME_FUNCTION_ENTRY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG64, IMAGE_TLS_DIRECTORY64};
use windows::Win32::System::SystemInformation::{IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64};
use windows::Win32::System::Threading::{CreateRemoteThread, GetExitCodeProcess, OpenProcess, PROCESS_ALL_ACCESS};

#[cfg(target_arch = "x86_64")]
const CURRENT_ARCH: IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "x86_64")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86_64")]
type IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY64;

#[cfg(target_arch = "x86")]
const CURRENT_ARCH: IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE_I386;
#[cfg(target_arch = "x86")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;
#[cfg(target_arch = "x86")]
type IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY32;

unsafe fn image_first_section(nt_headers: *const IMAGE_NT_HEADERS) -> *const IMAGE_SECTION_HEADER {
    (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER
}

fn image_snap_by_ordinal(thunk_ref: usize) -> bool {
    (thunk_ref as u64 & IMAGE_ORDINAL_FLAG64) != 0
}

#[repr(C)]
pub struct ManualMappingData {
    pub pLoadLibraryA: usize,
    pub pGetProcAddress: usize,
    pub pGetModuleHandleA: usize,
    pub pRtlAddFunctionTable: usize,
    pub pbase: *mut c_void,
    pub fdwReasonParam: u32,
    pub lpReservedParam: *mut c_void,
    pub SEHSupport: bool,
    pub SEHFailed: bool,
    pub hResult: HRESULT
}

type LoadLibraryAProc = unsafe extern "system" fn(PCSTR) -> HMODULE;
type GetProcAddressProc = unsafe extern "system" fn(HMODULE, PCSTR) -> *const usize;
type GetModuleHandleAProc = unsafe extern "system" fn(*const u8) -> isize;
type RtlAddFunctionTableProc = unsafe extern "system" fn(*const IMAGE_RUNTIME_FUNCTION_ENTRY, u32, u64) -> u8;
type DllEntryPointProc = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
type PImageTlsCallbackProc = unsafe extern "system" fn(dllhandle: *mut c_void, reason: u32, reserved: *mut c_void);

pub(super) fn mmap_load_library_int(pid: u32, path: &str) -> Result<HMODULE, Box<dyn std::error::Error>> {
    unsafe {
        let mut buffer = std::fs::read(path)?;
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        let hmodule = expand(
            process, &mut buffer, true, true,
            true, true, DLL_PROCESS_ATTACH
        )?;

        CloseHandle(process)?;

        Ok(hmodule)
    }
}

unsafe fn expand(
    h_proc: HANDLE,
    lib_buffer: &mut [u8],
    clear_header: bool,
    clear_non_needed_sections: bool,
    adjust_protections: bool,
    seh_exception_support: bool,
    fdw_reason: u32,
) -> Result<HMODULE, Box<dyn std::error::Error>> {
    unsafe {
        let dos_header = &mut *(lib_buffer.as_mut_ptr() as *mut IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D {
            return Err("Invalid file".into());
        }

        let ptr = lib_buffer.as_ptr() as usize;
        let nt_headers = &*((lib_buffer.as_ptr() as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
        let opt_header = &nt_headers.OptionalHeader;
        let file_header = &nt_headers.FileHeader;

        if file_header.Machine != CURRENT_ARCH {
            return Err("Invalid platform".into());
        }

        let lib_header_alloc = VirtualAllocEx(
            h_proc,
            None,
            opt_header.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if lib_header_alloc.is_null() {
            return Err(format!("Target process memory allocation failed: {:?}", GetLastError()).into());
        }
        
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
        if VirtualProtectEx(h_proc, lib_header_alloc, opt_header.SizeOfImage as usize, PAGE_EXECUTE_READWRITE, &mut old_protection).is_err() {
            VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
            return Err(format!("Failed to change protection of allocated memory: {:?}", GetLastError()).into());   
        }

        if WriteProcessMemory(h_proc, lib_header_alloc, lib_buffer.as_ptr() as *const c_void, 0x1000, None).is_err() {
            VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
            return Err(format!("Can't write file header: {:?}", GetLastError()).into());
        }

        let mut data: ManualMappingData = zeroed();
        let kernel32 = GetModuleHandleA(s!("kernel32"))?;
        let load_library = GetProcAddress(kernel32, s!("LoadLibraryA")).unwrap();
        let get_proc_address = GetProcAddress(kernel32, s!("GetProcAddress")).unwrap();
        let rtl_add_function_table = GetProcAddress(kernel32, s!("RtlAddFunctionTable")).unwrap();
        let get_module_handle = GetProcAddress(kernel32, s!("GetModuleHandleA")).unwrap();
        
        data.pLoadLibraryA = load_library as usize;
        data.pGetProcAddress = get_proc_address as usize;
        data.pGetModuleHandleA = get_module_handle as usize;
        if seh_exception_support {
            data.pRtlAddFunctionTable = rtl_add_function_table as usize;
        }
        data.pbase = lib_header_alloc as *mut c_void;
        data.fdwReasonParam = fdw_reason;
        data.SEHSupport = seh_exception_support;


        let section_header = image_first_section(nt_headers);
        for i in 0..file_header.NumberOfSections {
            let section = &*section_header.add(i as usize);
            println!(
                "Mapping section: {:?}. VirtAdd: {}, RawSize: {}, RawDataPtr: {}", 
                CStr::from_ptr(transmute(section.Name.as_ptr())).to_str().unwrap(), section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData
            );

            if section.SizeOfRawData != 0 {
                if WriteProcessMemory(
                    h_proc,
                    (lib_header_alloc as usize + section.VirtualAddress as usize) as *mut c_void,
                    (lib_buffer.as_ptr() as usize + section.PointerToRawData as usize) as *const c_void,
                    section.SizeOfRawData as usize,
                    None,
                ).is_err() {
                    VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
                    return Err(format!("Can't map sections: {:?}", GetLastError()).into());
                }
            }
        }

        let mapping_data_alloc = VirtualAllocEx(
            h_proc,
            None,
            size_of::<ManualMappingData>(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if mapping_data_alloc.is_null() {
            VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
            return Err(format!("Target process mapping allocation failed: {:?}", GetLastError()).into());
        }

        if WriteProcessMemory(
            h_proc,
            mapping_data_alloc,
            &data as *const _ as *const c_void,
            size_of::<ManualMappingData>(),
            None,
        ).is_err() {
            VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
            VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE)?;
            return Err(format!("Can't write mapping data: {:?}", GetLastError()).into());
        }

        let p_shellcode = VirtualAllocEx(h_proc, None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if p_shellcode.is_null() {
            VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
            VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE)?;
            return Err(format!("Memory shellcode allocation failed: {:?}", GetLastError()).into());
        }

        if WriteProcessMemory(h_proc, p_shellcode, shellcode as *const c_void, 0x1000, None).is_err() {
            VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
            VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE)?;
            VirtualFreeEx(h_proc, p_shellcode, 0, MEM_RELEASE)?;
            return Err(format!("Can't write shellcode: {:?}", GetLastError()).into());
        }

        let h_thread = CreateRemoteThread(h_proc, None, 0, Some(transmute(p_shellcode)), Some(mapping_data_alloc), 0, None);
        if h_thread.is_err() {
            VirtualFreeEx(h_proc, lib_header_alloc, 0, MEM_RELEASE)?;
            VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE)?;
            VirtualFreeEx(h_proc, p_shellcode, 0, MEM_RELEASE)?;
            return Err(format!("Thread creation failed: {:?}", GetLastError()).into());
        }

       CloseHandle(h_thread.unwrap())?;

        let mut data_checked: ManualMappingData = zeroed();
        while data_checked.hResult == HRESULT::default() {
            GetExitCodeProcess(h_proc, transmute(&mut data_checked.hResult.0 as *mut i32))?;
            if  data_checked.hResult.0 != STILL_ACTIVE.0 {
                return Err(format!("Process crashed ({}).", data_checked.hResult.0).to_string().into());
            }

            ReadProcessMemory(h_proc, mapping_data_alloc, &mut data_checked as *mut _ as *mut c_void, size_of::<ManualMappingData>(), None).unwrap();
            if data_checked.hResult == HRESULT(0x404040) {
                return Err("Wrong mapping pointer".to_string().into());
            } else if data_checked.hResult == HRESULT(0x505050) {
                println!("WARNING: Exception support failed!");
            } else if data_checked.hResult == HRESULT(0x606060) {
                return Err(format!("DllEntry failed ({}).", data_checked.hResult.0).into())
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let empty_buffer = vec![0u8; 1024 * 1024 * 20];

        if clear_header {
            WriteProcessMemory(h_proc, lib_header_alloc, empty_buffer.as_ptr() as *const c_void, 0x1000, None).unwrap();
        }

        if clear_non_needed_sections {
            for i in 0..file_header.NumberOfSections {
                let section = &*section_header.add(i as usize);
                if section.Misc.VirtualSize != 0 {
                    if (!seh_exception_support && &section.Name[..7] == b".pdata\0")
                        || &section.Name[..6] == b".rsrc\0\0"
                        || &section.Name[..6] == b".reloc\0"
                    {
                        WriteProcessMemory(h_proc, (lib_header_alloc as usize + section.VirtualAddress as usize) as *mut c_void, empty_buffer.as_ptr() as *const c_void, section.Misc.VirtualSize as usize, None).unwrap();
                    }
                }
            }
        }

        adjust_protections_and_cleanup(h_proc, lib_header_alloc, nt_headers, adjust_protections)?;

        if WriteProcessMemory(h_proc, p_shellcode, empty_buffer.as_ptr() as *const c_void, 0x1000, None).is_err() {
            println!("WARNING: can't clear shellcode");
        }

        if VirtualFreeEx(h_proc, p_shellcode, 0, MEM_RELEASE).is_err() {
            println!("WARNING: can't release shell code memory");
        }

        if VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE).is_err() {
            println!("WARNING: can't release mapping data memory");
        }

        Ok(HMODULE(data.pbase as isize))
    }
}

unsafe fn adjust_protections_and_cleanup(
    h_proc: HANDLE,
    p_target_base: *mut c_void,
    p_old_nt_headers: *const IMAGE_NT_HEADERS,
    adjust_protections: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let p_section_header = image_first_section(p_old_nt_headers);
    let p_old_file_header = &(*p_old_nt_headers).FileHeader;

    if adjust_protections {
        for i in 0..p_old_file_header.NumberOfSections {
            let section = &*p_section_header.add(i as usize);
            if section.Misc.VirtualSize != 0 {
                let mut old_protection = PAGE_PROTECTION_FLAGS(0);
                let new_protection = if (section.Characteristics.0 & IMAGE_SCN_MEM_WRITE.0) > 0 {
                    PAGE_READWRITE
                } else if (section.Characteristics.0 & IMAGE_SCN_MEM_EXECUTE.0) > 0 {
                    PAGE_EXECUTE_READ
                } else {
                    PAGE_READONLY
                };

                if VirtualProtectEx(
                    h_proc,
                    (p_target_base as usize + section.VirtualAddress as usize) as *mut c_void,
                    section.Misc.VirtualSize as usize,
                    new_protection,
                    &mut old_protection,
                ).is_err() {
                    return Err(format!(
                        "FAIL: section {} not set as {:#X}: {:?}",
                        std::str::from_utf8(&section.Name).unwrap_or_default(),
                        new_protection.0,
                        GetLastError()
                    ).into());
                }
            }
        }

        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            h_proc,
            p_target_base as *mut c_void,
            (*p_section_header).VirtualAddress as usize,
            PAGE_READONLY,
            &mut old_protection,
        )?;
    }

    Ok(())
}

#[no_mangle]
#[inline(always)]
unsafe fn shellcode(m_mapping: *mut ManualMappingData) {
    if m_mapping as usize == 0 {
        (*m_mapping).hResult = HRESULT(0x404040);
    }
    
    let mapping = &mut *m_mapping;
    let hmodule = mapping.pbase;

    let dos_header = &*(hmodule as *const IMAGE_DOS_HEADER);
    let nt_headers = &*((hmodule as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let opt_header = &nt_headers.OptionalHeader;
    let file_header = &nt_headers.FileHeader;

    #[cfg(target_arch = "x86_64")]
    let _rtl_add_function_table: RtlAddFunctionTableProc = transmute(mapping.pRtlAddFunctionTable);
    let _dll_main: DllEntryPointProc = transmute(hmodule as usize + opt_header.AddressOfEntryPoint as usize);
    let loadLibraryA: LoadLibraryAProc = transmute(mapping.pLoadLibraryA);
    let getProcAddress: GetProcAddressProc = transmute(mapping.pGetProcAddress);

    let location_delta = mapping.pbase as usize - opt_header.ImageBase as usize;
    if location_delta != 0 {
        if opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize].Size != 0 {
            let mut p_reloc_data = (hmodule as usize + opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize].VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;
            let p_reloc_end = (p_reloc_data as usize + opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize].Size as usize) as *mut IMAGE_BASE_RELOCATION;
            
            while p_reloc_data < p_reloc_end && (*p_reloc_data).SizeOfBlock != 0 {
                let amount_of_entries = ((*p_reloc_data).SizeOfBlock - std::mem::size_of::<IMAGE_BASE_RELOCATION>() as u32) / std::mem::size_of::<u16>() as u32;
                let p_relative_info: *mut u16 = transmute(p_reloc_data.add(1));
                
                let mut i = 0;
                while i != amount_of_entries {
                    let p_relative_info = p_relative_info.add(i as usize);

                    if (p_relative_info.read() >> 0xC) == 0xA {
                        let p_patch = (hmodule as usize + (*p_reloc_data).VirtualAddress as usize + (p_relative_info.read() & 0xFFF) as usize) as *mut usize;
                        p_patch.write(p_patch.read() + location_delta as usize);
                    }

                    i += 1;
                }

                p_reloc_data = (p_reloc_data as usize + (*p_reloc_data).SizeOfBlock as usize) as *mut IMAGE_BASE_RELOCATION;
            }
        }
    }
    
    if opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize].Size != 0 {
        let mut p_import_descr = (hmodule as usize + opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize].VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;
        while (*p_import_descr).Name != 0 {

            let sz_mod = PCSTR((hmodule as usize + (*p_import_descr).Name as usize) as *mut u8);
            let h_dll = loadLibraryA(sz_mod);

            let mut p_thunk_ref = (hmodule as usize + (*p_import_descr).Anonymous.OriginalFirstThunk as usize) as *mut usize;
            let mut p_func_ref = (hmodule as usize + (*p_import_descr).FirstThunk as usize) as *mut usize;
            
            p_thunk_ref = match p_thunk_ref as usize {
                0 => p_func_ref,
                _ => p_thunk_ref
            };

            while p_thunk_ref.read() != 0 {
                *p_func_ref = match p_thunk_ref.read() & IMAGE_ORDINAL_FLAG64 as usize {
                    0 => {
                        let p_import = &*((hmodule as usize + *p_thunk_ref as usize) as *const IMAGE_IMPORT_BY_NAME);
                        let sz_import = PCSTR(p_import.Name.as_ptr() as *const u8);
                        getProcAddress(h_dll, sz_import) as usize
                    }
                    _ => {
                        getProcAddress(h_dll, PCSTR(((*p_thunk_ref) & 0xFFFF) as *const u8)) as usize
                    }
                };

                p_thunk_ref = p_thunk_ref.add(1);
                p_func_ref = p_func_ref.add(1);

            }

            p_import_descr = p_import_descr.add(1);
        }
    }

    
    let image_tls_directory = &*((hmodule as usize + opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize].VirtualAddress as usize) as *mut IMAGE_TLS_DIRECTORY);
    let mut callback: *mut PImageTlsCallbackProc = transmute(image_tls_directory.AddressOfCallBacks as *mut usize);
    while callback.read() as usize != 0 {
        callback.read()(hmodule, DLL_PROCESS_ATTACH, 0 as *mut c_void);
        callback = callback.add(1);
    }
 
    #[cfg(target_arch = "x86_64")]
    {
        if mapping.SEHSupport {
            let excep = &opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION.0 as usize];

            if excep.Size != 0 && mapping.pRtlAddFunctionTable != 0 {
                if _rtl_add_function_table(
                    (hmodule as usize + excep.VirtualAddress as usize) as *mut IMAGE_RUNTIME_FUNCTION_ENTRY,
                    excep.Size / std::mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>() as u32,
                    hmodule as u64,
                ) == 0 {
                    mapping.SEHFailed = true;
                } else {
                    mapping.SEHFailed = false;
                }
            }
        }
    }

    _dll_main(hmodule, mapping.fdwReasonParam, mapping.lpReservedParam);

    if mapping.SEHSupport && mapping.SEHFailed {
        mapping.hResult = HRESULT(0x505050);
        return;
    }

    mapping.hResult = HRESULT(0x1);
}