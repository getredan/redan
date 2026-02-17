fn main() {
    println!("cargo:rustc-link-lib=krun");
    println!("cargo:rerun-if-changed=templates/");
}
