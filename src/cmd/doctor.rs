use std::path::Path;

use super::exec::parse_secret;
use redan::image;
use redan::image_meta::ImageMeta;

#[expect(
    clippy::too_many_lines,
    reason = "one linear sequence of independent environment checks, splitting it would only scatter them"
)]
pub(crate) fn run(secret_specs: &[String], check_image: Option<&str>) {
    let mut ok = true;

    // KVM
    match redan::check_kvm() {
        Ok(()) => println!("[ok]   kvm: /dev/kvm accessible"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("[err]  kvm: not found");
            println!("       enable KVM in your kernel or BIOS settings");
            ok = false;
        }
        Err(e) => {
            println!("[err]  kvm: exists but not accessible: {e}");
            println!("       add your user to the kvm group: sudo usermod -aG kvm $USER");
            ok = false;
        }
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

    if let Some(dir) = find_lib("libkrun.so") {
        println!("[ok]   libkrun: {dir}/libkrun.so");
    } else {
        println!("[err]  libkrun: not found");
        println!("       install libkrun from your distro packages");
        ok = false;
    }

    if let Some(dir) = find_lib("libkrunfw.so") {
        println!("[ok]   libkrunfw: {dir}/libkrunfw.so");
    } else {
        println!("[err]  libkrunfw: not found");
        println!("       install libkrunfw from your distro packages");
        ok = false;
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

    // Check image freshness
    for name in &images {
        if let Ok(path) = image::image_path(name)
            && let Some(meta) = ImageMeta::load(&path)
            && let Some(days) = meta.age_days()
            && days > 30
        {
            println!("[warn] image {name}: {days} days old");
            println!("       run: redan image update {name}");
        }
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

    // ANTHROPIC_API_KEY check (when claude-code image exists)
    if images.contains(&"claude-code".to_string()) {
        if std::env::var("ANTHROPIC_API_KEY").is_ok_and(|v| !v.is_empty()) {
            println!("[ok]   ANTHROPIC_API_KEY: set");
        } else {
            println!("[warn] ANTHROPIC_API_KEY: not set");
            println!(
                "       needed for zero-config Claude Code: export ANTHROPIC_API_KEY=sk-ant-..."
            );
        }
    }

    // Chrome/Chromium (informational, not required)
    if let Some(path) = redan::browser::find_chrome() {
        println!("[ok]   chrome: {}", path.display());
    } else {
        println!("[info] chrome: not found (optional, needed for --browser)");
    }

    // Validate secrets (never print values)
    for spec in secret_specs {
        let env_label = spec.split_once('=').map_or("(invalid)", |(name, _)| name);

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

pub(crate) fn dir_size(path: &std::path::Path) -> u64 {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// `bytes / unit` rounded to one decimal place (ties to even), as `"N.D"`.
/// Integer arithmetic keeps large sizes exact, unlike a round trip through `f64`.
fn one_decimal(bytes: u64, unit: u64) -> String {
    let scaled = u128::from(bytes) * 10;
    let unit = u128::from(unit);
    let (mut tenths, rem) = (scaled / unit, scaled % unit);
    if rem * 2 > unit || (rem * 2 == unit && tenths % 2 == 1) {
        tenths += 1;
    }
    format!("{}.{}", tenths / 10, tenths % 10)
}

pub(crate) fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{} KB", one_decimal(bytes, KB))
    } else if bytes < GB {
        format!("{} MB", one_decimal(bytes, MB))
    } else {
        format!("{} GB", one_decimal(bytes, GB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_bytes_picks_unit_and_rounds_to_one_decimal() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(1023), "1023 B");
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(1024 * 1024 - 1), "1024.0 KB");
        assert_eq!(humanize_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(humanize_bytes(3 * 1024 * 1024 * 1024 / 2), "1.5 GB");
    }

    #[test]
    fn humanize_bytes_rounds_exact_ties_to_even() {
        assert_eq!(humanize_bytes(1280), "1.2 KB");
        assert_eq!(humanize_bytes(1792), "1.8 KB");
    }

    #[test]
    fn humanize_bytes_handles_u64_max() {
        assert_eq!(humanize_bytes(u64::MAX), "17179869184.0 GB");
    }
}
