fn main() {
    println!("cargo:rustc-link-lib=krun");

    // Help users who don't have libkrun installed
    if std::process::Command::new("pkg-config")
        .args(["--exists", "libkrun"])
        .status()
        .is_ok_and(|s| !s.success())
    {
        println!(
            "cargo:warning=libkrun not found. Install it: \
             Arch: pacman -S libkrun | Fedora: dnf install libkrun-devel"
        );
    }
}
