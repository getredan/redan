fn main() {
    println!("cargo:rustc-link-lib=krun");

    // Help users who don't have libkrun installed.
    // Skip the warning in CI (stubs provide link-time symbols;
    // real libkrun is only needed at runtime).
    if std::env::var_os("CI").is_some() {
        return;
    }
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
