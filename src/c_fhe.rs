use crate::testnet::TESTNET1_FHE;
use std::mem;
use std::ptr::copy_nonoverlapping;

// I think go can tell us the length of the array
#[no_mangle]
pub extern "C" fn c_fhe_add(
    bytes: *const u8,
    bytes_length: libc::size_t,
    output: *mut *mut u8,
    output_length: *mut i64,
) -> i32 {
    let input: &[u8] = unsafe { std::slice::from_raw_parts(bytes, bytes_length) };

    let result = TESTNET1_FHE.add(input);

    match result {
        Ok(res) => {
            let result_length = res.len();

            unsafe {
                *output_length = result_length as i64;

                let buffer: *mut u8 = libc::malloc(result_length * mem::size_of::<u8>()) as *mut u8;
                copy_nonoverlapping(res.as_ptr(), buffer, res.len());

                *output = buffer;
                0
            }
        }
        Err(_) => {
            unsafe {
                *output_length = 0;
                *output = std::ptr::null_mut();
            };
            -1
        }
    }
}

// I think go can tell us the length of the array
#[no_mangle]
pub extern "C" fn fhe_free(bytes: *const u8) {
    println!("Free");
    unsafe { libc::free(bytes as *mut libc::c_void) };
}
