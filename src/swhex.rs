use std::path::Path;
use std::time::Duration;

use windows::core::{s, BSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, FreeLibrary, HMODULE, INVALID_HANDLE_VALUE, LPARAM, WPARAM};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use windows::Win32::UI::WindowsAndMessaging::{GetGUIThreadInfo, PostThreadMessageW, SetWindowsHookExW, UnhookWindowsHookEx, GUITHREADINFO, HOOKPROC, WH_GETMESSAGE, WM_NULL};

use crate::misc::query_hmodule;

pub(super) fn swhex_load_library_int(pid: u32, sz_path: &str) -> Result<HMODULE, Box<dyn std::error::Error>> {
    unsafe {
        let sz_hmodule = Path::new(sz_path).file_name().unwrap().to_str().unwrap();
        let tid = find_ui_thread(pid);

        if tid.is_none() {
            return Err(format!("Failed to find ui tid for pid #{}", pid).into());
        }

        let hmodule = LoadLibraryW(PCWSTR::from_raw(BSTR::from(sz_path).into_raw())).unwrap();
        let hproc: HOOKPROC = std::mem::transmute(GetProcAddress(hmodule, s!("Wndproc")));
        // LRESULT Wndproc(HWND unnamedParam1,UINT unnamedParam2,WPARAM unnamedParam3,LPARAM unnamedParam4)
        let hook = SetWindowsHookExW(WH_GETMESSAGE, hproc, hmodule, tid.unwrap()).unwrap();

        PostThreadMessageW(tid.unwrap(), WM_NULL, WPARAM(0), LPARAM(0)).unwrap();
        std::thread::sleep(Duration::from_secs(1));

        UnhookWindowsHookEx(hook).unwrap();
        FreeLibrary(hmodule).unwrap();
        
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;
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

unsafe fn find_ui_thread(pid: u32) -> Option<u32> {
    let p_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).unwrap();
    if p_snapshot == INVALID_HANDLE_VALUE  {
        return None;
    }

    let mut entry32 = THREADENTRY32::default();
    entry32.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    Thread32First(p_snapshot, &mut entry32).unwrap();

    let mut tid: u32 = 0;
    while Thread32Next(p_snapshot, &mut entry32).is_ok() {
        if entry32.th32OwnerProcessID == pid {
            let mut gui_thread_info = GUITHREADINFO::default();
            gui_thread_info.cbSize = std::mem::size_of::<GUITHREADINFO>() as u32;
            if GetGUIThreadInfo(entry32.th32ThreadID, &mut gui_thread_info).is_ok() {
                tid = entry32.th32ThreadID;
                break;
            }

            tid = entry32.th32ThreadID;
        }
    }

    Some(tid)
}
