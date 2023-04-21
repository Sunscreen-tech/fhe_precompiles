use crate::testnet::one::FHE;
use crate::FheError;

use std::ffi::CString;
use std::mem;
use std::ptr::copy_nonoverlapping;

macro_rules! create_c_precompile_function {
    ($name: ident) => {
        paste::item! {
            /// Call FHE computation from C. Returns an error code that is 0 on
            /// success; errors are encoded using the `FheError::from`
            /// implementation. A more informative string related to the error
            /// code can be retrieved using the
            /// [`error_code_to_str`][crate::FheError::error_code_to_str]
            /// method.
            ///
            /// * `bytes` - The byte packed input to the specific FHE computation.
            /// * `bytes_length` - The length of the byte array
            /// * `output` - A double pointer where the result will be stored on success.
            /// * `output_length` - The length of the output data on success.
            #[no_mangle]
            pub extern "C" fn [< c_fhe_ $name >] (
                bytes: *const u8,
                bytes_length: libc::size_t,
                output: *mut *mut u8,
                output_length: *mut i64,
            ) -> i32 {
                let input: &[u8] = unsafe { std::slice::from_raw_parts(bytes, bytes_length) };

                let result = FHE.$name(input);

                match result {
                    Ok(res) => {
                        let result_length = res.len();

                        unsafe {
                            *output_length = result_length as i64;

                            let buffer: *mut u8 =
                                libc::malloc(result_length * mem::size_of::<u8>()) as *mut u8;
                            copy_nonoverlapping(res.as_ptr(), buffer, res.len());

                            *output = buffer;
                            0
                        }
                    }
                    Err(e) => {
                        unsafe {
                            *output_length = 0;
                            *output = std::ptr::null_mut();
                        };
                        e.into()
                    }
                }
            }
        }
    };
}

#[no_mangle]
pub extern "C" fn fhe_free(bytes: *const u8) {
    unsafe { libc::free(bytes as *mut libc::c_void) };
}

#[no_mangle]
pub extern "C" fn fhe_error(error_code: i32) -> *const libc::c_char {
    let cstr = FheError::error_code_to_str(error_code);
    let bytes = cstr.as_bytes();
    CString::new(bytes).unwrap().into_raw()
}

create_c_precompile_function!(add);
create_c_precompile_function!(add_plain);
create_c_precompile_function!(subtract);
create_c_precompile_function!(subtract_plain);
create_c_precompile_function!(multiply);
create_c_precompile_function!(encrypt_zero);
