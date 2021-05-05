#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use data_ocalls;
use rtc_types::*;
use sgx_types::*;
use sgx_urts;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
