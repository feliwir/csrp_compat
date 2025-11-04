// build.rs

fn main() {
    cc::Build::new().file("srp.c").compile("csrp");

    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");
}
