#![allow(dead_code)]
#![allow(unused_variables)]

use crt::crt_load_library_int;
use misc::HResult;
use mmap::mmap_load_library_int;
use ntcrt::ntcrt_load_library_int;
use swhex::swhex_load_library_int;
use std::ffi::{c_char, CStr};

mod mmap;
mod crt;
mod ntcrt;
mod swhex;
mod misc;

#[no_mangle]
pub unsafe extern "C" fn mmap_load_library(process_id: u32, path: *mut c_char) -> HResult {
    mmap_load_library_int(process_id, unsafe { CStr::from_ptr(path).to_str().unwrap() }).into()
}

#[no_mangle]
pub unsafe extern "C" fn swhex_load_library(process_id: u32, path: *mut c_char) -> HResult {
    swhex_load_library_int(process_id, unsafe { CStr::from_ptr(path).to_str().unwrap() }).into()
}

#[no_mangle]
pub unsafe extern "C" fn ntcrt_load_library(process_id: u32, path: *mut c_char) -> HResult {
    ntcrt_load_library_int(process_id, unsafe { CStr::from_ptr(path).to_str().unwrap() }).into()
}

#[no_mangle]
pub unsafe extern "C" fn crt_load_library(process_id: u32, path: *mut c_char) -> HResult {
    crt_load_library_int(process_id, unsafe { CStr::from_ptr(path).to_str().unwrap() }).into()
}

#[no_mangle]
pub unsafe extern "C" fn finalize(result: HResult) {
   drop(result);
}