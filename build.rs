// build.rs

fn main() {
    cc::Build::new().file("srp.c").include(".").compile("csrp");

    // Check for windows
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=static=libssl");
        println!("cargo:rustc-link-lib=static=libcrypto");
        // WinCrypt
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=user32");
    }
    #[cfg(not(target_os = "windows"))]
    {
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }
}
