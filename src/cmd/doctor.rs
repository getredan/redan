use std::path::Path;

use super::exec::parse_secret;
use redan::image;

pub(crate) fn run(secret_specs: &[String], check_image: Option<&str>) {
    let mut ok = true;

    // KVM
    let kvm_path = Path::new("/dev/kvm");
    if kvm_path.exists() {
        match std::fs::File::open(kvm_path) {
            Ok(_) => println!("[ok]   kvm: /dev/kvm accessible"),
            Err(e) => {
                println!("[err]  kvm: exists but not accessible: {e}");
                println!("       add your user to the kvm group: sudo usermod -aG kvm $USER");
                ok = false;
            }
        }
    } else {
        println!("[err]  kvm: not found");
        println!("       enable KVM in your kernel or BIOS settings");
        ok = false;
    }

    // Shared library search paths
    let lib_paths = [
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ];

    let find_lib = |name: &str| -> Option<&str> {
        lib_paths
            .iter()
            .find(|dir| Path::new(&format!("{dir}/{name}")).exists())
            .copied()
    };

    match find_lib("libkrun.so") {
        Some(dir) => println!("[ok]   libkrun: {dir}/libkrun.so"),
        None => {
            println!("[err]  libkrun: not found");
            println!("       install libkrun from your distro packages");
            ok = false;
        }
    }

    match find_lib("libkrunfw.so") {
        Some(dir) => println!("[ok]   libkrunfw: {dir}/libkrunfw.so"),
        None => {
            println!("[err]  libkrunfw: not found");
            println!("       install libkrunfw from your distro packages");
            ok = false;
        }
    }

    // Images
    let images = image::list();
    if images.is_empty() {
        println!("[warn] images: none");
        println!(
            "       create one with: redan image create dev --packages 'curl ca-certificates'"
        );
    } else {
        println!("[ok]   images: {}", images.join(", "));
    }

    if let Some(name) = check_image {
        match image::image_path(name) {
            Ok(p) if p.exists() => println!("[ok]   image {name}: found"),
            Ok(_) => {
                println!("[err]  image {name}: not found");
                println!("       run: redan image create {name} --packages '...'");
                ok = false;
            }
            Err(e) => {
                println!("[err]  image {name}: {e}");
                ok = false;
            }
        }
    }

    // Validate secrets (never print values)
    for spec in secret_specs {
        let env_label = spec
            .split_once('=')
            .map(|(name, _)| name)
            .unwrap_or("(invalid)");

        match parse_secret(spec) {
            Ok((env_name, binding)) => {
                let provider = if spec.contains("vault://") {
                    "vault"
                } else {
                    "literal"
                };
                println!(
                    "[ok]   {env_name}: {provider}  hosts: {}",
                    binding.allowed_hosts().join(", "),
                );
            }
            Err(e) => {
                println!("[err]  {env_label}: {e}");
                ok = false;
            }
        }
    }

    println!("[info] image dir: {}", image::image_dir().display());

    if ok {
        println!("\nready to go");
    } else {
        println!("\nsome checks failed");
        std::process::exit(1);
    }
}

pub(crate) fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    Ok(total)
}

pub(crate) fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    }
}
