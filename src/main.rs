// typedef enum
// {
//     SRP_NG_1024,
//     SRP_NG_2048,
//     SRP_NG_4096,
//     SRP_NG_8192,
//     SRP_NG_CUSTOM
// } SRP_NGType;

// typedef enum
// {
//     SRP_SHA1,
//     SRP_SHA224,
//     SRP_SHA256,
//     SRP_SHA384,
//     SRP_SHA512
// } SRP_HashAlgorithm;

use rand::TryRngCore;
use sha2::Sha512;
use srp::{groups::G_2048, server::SrpServer};

#[repr(i32)]
enum SrpNGType {
    NG1024 = 0,
    NG2048 = 1,
    NG4096 = 2,
    NG8192 = 3,
    NGCUSTOM = 4,
}

#[repr(i32)]
enum SrpHashAlgorithm {
    SHA1 = 0,
    SHA224 = 1,
    SHA256 = 2,
    SHA384 = 3,
    SHA512 = 4,
}

unsafe extern "C" {
    // FFI bindings would go here
    fn srp_create_salted_verification_key(
        alg: SrpHashAlgorithm,
        ng_type: SrpNGType,
        username: *const u8,
        password: *const u8,
        len_password: i32,
        bytes_s: *mut *const u8,
        len_s: *mut i32,
        bytes_v: *mut *const u8,
        len_v: *mut i32,
        n_hex: *const u8,
        g_hex: *const u8,
    );

    // void srp_create_salted_verification_key( SRP_HashAlgorithm alg,
    //                                      SRP_NGType ng_type, const char * username,
    //                                      const unsigned char * password, int len_password,
    //                                      const unsigned char ** bytes_s, int * len_s,
    //                                      const unsigned char ** bytes_v, int * len_v,
    //                                      const char * n_hex, const char * g_hex );

    fn srp_user_new(
        alg: SrpHashAlgorithm,
        ng_type: SrpNGType,
        username: *const u8,
        bytes_password: *const u8,
        len_password: i32,
        n_hex: *const u8,
        g_hex: *const u8,
    ) -> *mut std::ffi::c_void;

    // struct SRPUser *      srp_user_new( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username,
    //                                 const unsigned char * bytes_password, int len_password,
    //                                 const char * n_hex, const char * g_hex );

    fn srp_user_start_authentication(
        usr: *mut std::ffi::c_void,
        username: *const *const u8,
        bytes_a: *mut *const u8,
        len_a: *mut i32,
    );

    // void                  srp_user_start_authentication( struct SRPUser * usr, const char ** username,

    fn srp_user_process_challenge(
        usr: *mut std::ffi::c_void,
        bytes_s: *const u8,
        len_s: i32,
        bytes_B: *const u8,
        len_B: i32,
        bytes_M: *mut *const u8,
        len_M: *mut i32,
    );

    // void                  srp_user_process_challenge( struct SRPUser * usr,
    //                                               const unsigned char * bytes_s, int len_s,
    //                                               const unsigned char * bytes_B, int len_B,
    //                                               const unsigned char ** bytes_M, int * len_M );

    fn srp_verifier_new(
        alg: SrpHashAlgorithm,
        ng_type: SrpNGType,
        username: *const u8,
        bytes_s: *const u8,
        len_s: i32,
        bytes_v: *const u8,
        len_v: i32,
        bytes_A: *const u8,
        len_A: i32,
        bytes_B: *mut *const u8,
        len_B: *mut i32,
        n_hex: *const u8,
        g_hex: *const u8,
    ) -> *mut std::ffi::c_void;

    // struct SRPVerifier *  srp_verifier_new( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username,
    //                                     const unsigned char * bytes_s, int len_s,
    //                                     const unsigned char * bytes_v, int len_v,
    //                                     const unsigned char * bytes_A, int len_A,
    //                                     const unsigned char ** bytes_B, int * len_B,
    //                                     const char * n_hex, const char * g_hex );

    fn srp_verifier_verify_session(
        ver: *mut std::ffi::c_void,
        user_M: *const u8,
        bytes_HAMK: *mut *const u8,
    );

    // void                  srp_verifier_verify_session( struct SRPVerifier * ver,
    //                                                const unsigned char * user_M,
    //                                                const unsigned char ** bytes_HAMK );

}

fn main() {
    let mut rng = rand::rngs::OsRng;
    let username = b"alice\0";
    let password = b"password123\0";

    unsafe {
        let mut bytes_s: *const u8 = std::ptr::null_mut();
        let mut len_s: i32 = 0;
        let mut bytes_v: *const u8 = std::ptr::null_mut();
        let mut len_v: i32 = 0;
        let mut bytes_a: *const u8 = std::ptr::null_mut();
        let mut len_a: i32 = 0;

        srp_create_salted_verification_key(
            SrpHashAlgorithm::SHA512,
            SrpNGType::NG2048,
            username.as_ptr(),
            password.as_ptr(),
            password.len() as i32 - 1,
            &mut bytes_s,
            &mut len_s,
            &mut bytes_v,
            &mut len_v,
            std::ptr::null(),
            std::ptr::null(),
        );

        let salt = std::slice::from_raw_parts(bytes_s, len_s as usize);
        println!("SALT: {:?}\n", salt);
        let verifier = std::slice::from_raw_parts(bytes_v, len_v as usize);
        println!("VERIFIER: {:?}\n", verifier);

        let usr = srp_user_new(
            SrpHashAlgorithm::SHA512,
            SrpNGType::NG2048,
            username.as_ptr(),
            password.as_ptr(),
            password.len() as i32 - 1,
            std::ptr::null(),
            std::ptr::null(),
        );

        srp_user_start_authentication(usr, &username.as_ptr(), &mut bytes_a, &mut len_a);

        let bytes_a = std::slice::from_raw_parts(bytes_a, len_a as usize);
        println!("BYTES_A: {:?}\n", bytes_a);

        // Client->Server: bytes_a
        let srp_server = SrpServer::<Sha512>::new(&G_2048);

        let mut b = [0u8; 64];
        rng.try_fill_bytes(&mut b).expect("Failed to fill bytes");
        let b_pub = srp_server
            .compute_public_ephemeral_csrp(&b, std::slice::from_raw_parts(bytes_v, len_v as usize));

        let mut csrp_b: *const u8 = std::ptr::null_mut();
        let mut csrp_len = 0;
        let csrp_ver = srp_verifier_new(
            SrpHashAlgorithm::SHA512,
            SrpNGType::NG2048,
            username.as_ptr(),
            bytes_s,
            len_s,
            bytes_v,
            len_v,
            bytes_a.as_ptr(),
            len_a,
            &mut csrp_b,
            &mut csrp_len,
            std::ptr::null(),
            std::ptr::null(),
        );

        let csrp_b = std::slice::from_raw_parts(csrp_b, csrp_len as usize);

        // Server->Client: (b_pub, salt)
        let mut bytes_m: *const u8 = std::ptr::null_mut();
        let mut len_m: i32 = 0;

        srp_user_process_challenge(
            usr,
            bytes_s,
            len_s,
            b_pub.as_ptr(),
            b_pub.len() as i32,
            &mut bytes_m,
            &mut len_m,
        );

        let bytes_m = std::slice::from_raw_parts(bytes_m, len_m as usize);
        println!("BYTES_M: {:?}\n", bytes_m);

        // Exclude the trailing null byte for username
        let username_nozero = &username[..username.len() - 1];

        // Client->Server: bytes_m
        let srp_verifier = srp_server
            .process_reply_csrp(username_nozero, salt, &b, verifier, bytes_a)
            .expect("Failed to process reply");

        srp_verifier
            .verify_client(bytes_m)
            .expect("Failed to verify client");
    }
}
