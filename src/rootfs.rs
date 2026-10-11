//! Host-side writes into a guest's root filesystem.
//!
//! The rootfs directory is the guest's `/` over virtio-fs, so the guest can
//! replace anything in it with a symlink, and the link is still there when the
//! next session prepares the image. Inside the guest, a link like
//! `/etc/redan/policy -> ../../../../../../.bashrc` or
//! `/home/dev/.claude -> /home/you` stays in the guest. A host that writes
//! through it with plain `std::fs` lands in your home instead. So every write
//! the host makes into a rootfs goes through [`Rootfs`], which resolves paths
//! with `openat2(RESOLVE_IN_ROOT)`: symlinks and `..` resolve the way the guest
//! sees them, and never leave the rootfs. See
//! <https://man7.org/linux/man-pages/man2/openat2.2.html>.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Component, Path, PathBuf};

/// `struct open_how` from `linux/openat2.h`, in its first version, which
/// every kernel with openat2 accepts. libc's `open_how` is `non_exhaustive`,
/// so it can only be built zeroed through `unsafe`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// A guest root filesystem, opened so that writes into it can't leave it.
pub struct Rootfs {
    dir: File,
}

impl Rootfs {
    /// Open the rootfs at `path`.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if `path` isn't a directory you can open.
    pub fn open(path: &Path) -> io::Result<Self> {
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(path)?;
        Ok(Self { dir })
    }

    /// Create the directory at `path` and any missing parents, like
    /// `std::fs::create_dir_all`, and return it.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if a component can't be created, or exists and
    /// isn't a directory as the guest sees it, and `InvalidInput` if `path`
    /// has a `..`.
    pub fn create_dir_all(&self, path: &Path) -> io::Result<File> {
        let mut dir = self.dir.try_clone()?;
        let mut walked = PathBuf::new();
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{} isn't a plain path", path.display()),
                    ));
                }
            };
            mkdir(&dir, name)?;
            walked.push(name);
            dir = self.open_in_root(&walked, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
        Ok(dir)
    }

    /// Create the file at `path`, or truncate it, like `File::create`. Its
    /// parent has to exist.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the file can't be opened, and `InvalidInput`
    /// if what's there isn't a regular file or has other hard links. A FIFO
    /// fails right away instead of waiting for a reader.
    pub fn create(&self, path: &Path) -> io::Result<File> {
        use std::os::unix::fs::MetadataExt as _;

        // Not truncated on open: a hard link isn't a path RESOLVE_IN_ROOT
        // could catch, so the file is checked first, through the opened fd.
        let file = self.open_in_root(
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK | libc::O_NOCTTY,
            0o644,
        )?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} isn't a regular file", path.display()),
            ));
        }
        if meta.nlink() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} has other hard links", path.display()),
            ));
        }
        file.set_len(0)?;
        Ok(file)
    }

    /// Whether `path` is a directory as the guest sees it.
    #[must_use]
    pub fn is_dir(&self, path: &Path) -> bool {
        self.open_in_root(path, libc::O_PATH | libc::O_DIRECTORY, 0)
            .is_ok()
    }

    fn open_in_root(
        &self,
        path: &Path,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> io::Result<File> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let how = OpenHow {
            flags: u64::from((flags | libc::O_CLOEXEC).cast_unsigned()),
            mode: u64::from(mode),
            resolve: libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: openat2(2) takes a directory fd, a NUL-terminated path, a
        // pointer to a `struct open_how` and that struct's size. `self.dir` is
        // an open directory for the whole call, `path` is a C string owned by
        // this frame, and `how` is an initialized `#[repr(C)]` copy of the
        // kernel's struct on the stack, passed with its own size.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.dir.as_raw_fd(),
                path.as_ptr(),
                &raw const how,
                size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::c_int::try_from(fd)
            .map_err(|_| io::Error::other(format!("openat2 returned {fd}, not an fd")))?;
        // SAFETY: openat2 succeeded, so `fd` is a new open file descriptor
        // that nothing else owns.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
}

/// Create `name` in `dir`, or leave it if it's already there. `mkdirat`
/// doesn't follow a symlink at `name`, it reports that it exists, and the
/// caller then resolves it inside the rootfs.
fn mkdir(dir: &File, name: &OsStr) -> io::Result<()> {
    let name = CString::new(name.as_bytes())?;
    // SAFETY: mkdirat(2) takes a directory fd, a NUL-terminated path and a
    // mode. `dir` is an open directory for the whole call and `name` is a C
    // string owned by this frame.
    let ret = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) };
    if ret == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::AlreadyExists {
        return Ok(());
    }
    Err(err)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// A temp dir standing in for your files, with `victim` in it. It sits
    /// next to the test's rootfs, since both are in the temp dir.
    fn your_files() -> tempfile::TempDir {
        let yours = tempfile::tempdir().unwrap();
        std::fs::write(yours.path().join("victim"), "yours").unwrap();
        yours
    }

    fn assert_untouched(yours: &Path) {
        let names: Vec<_> = std::fs::read_dir(yours)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["victim"]);
        assert_eq!(
            std::fs::read_to_string(yours.join("victim")).unwrap(),
            "yours"
        );
    }

    #[test]
    fn create_dir_all_and_create_write_inside_the_rootfs() {
        let rootfs = tempfile::tempdir().unwrap();
        let root = Rootfs::open(rootfs.path()).unwrap();

        root.create_dir_all(Path::new("/etc/redan")).unwrap();
        write!(
            root.create(Path::new("/etc/redan/policy")).unwrap(),
            "policy"
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(rootfs.path().join("etc/redan/policy")).unwrap(),
            "policy"
        );
        assert!(root.is_dir(Path::new("etc/redan")));
        assert!(!root.is_dir(Path::new("etc/redan/policy")));
    }

    #[test]
    fn links_out_of_the_rootfs_resolve_inside_it() {
        let yours = your_files();
        let absolute = yours.path().display().to_string();
        let relative = format!("../{}", yours.path().file_name().unwrap().display());
        let climbing = format!("../../../../../../../..{absolute}");
        let magic = format!("/proc/self/root{absolute}");
        for target in [absolute, relative, climbing, magic] {
            let rootfs = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(&target, rootfs.path().join("etc")).unwrap();
            let root = Rootfs::open(rootfs.path()).unwrap();

            let _ = root.create_dir_all(Path::new("etc/redan"));
            let _ = root.create(Path::new("etc/victim"));

            assert_untouched(yours.path());
        }
    }

    #[test]
    fn create_through_a_link_to_your_file_stays_in_the_rootfs() {
        let yours = your_files();
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir(rootfs.path().join("etc")).unwrap();
        std::os::unix::fs::symlink(
            yours.path().join("victim"),
            rootfs.path().join("etc/policy"),
        )
        .unwrap();
        let root = Rootfs::open(rootfs.path()).unwrap();

        let _ = root.create(Path::new("etc/policy"));

        assert_untouched(yours.path());
    }

    /// A hard link in the image to one of your files isn't a path to
    /// resolve, so `RESOLVE_IN_ROOT` can't catch it. The guest can only link
    /// to what it can already reach, but an image could ship one.
    #[test]
    fn create_refuses_a_file_with_another_hard_link() {
        let yours = your_files();
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::hard_link(yours.path().join("victim"), rootfs.path().join("policy")).unwrap();
        let root = Rootfs::open(rootfs.path()).unwrap();

        assert!(root.create(Path::new("policy")).is_err());
        assert_untouched(yours.path());
    }

    /// Absolute links in an image only make sense inside the guest, like
    /// Fedora's `/etc/ssl/certs -> /etc/pki/tls/certs`.
    #[test]
    fn absolute_links_resolve_against_the_rootfs() {
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("etc/pki/tls/certs")).unwrap();
        std::fs::create_dir_all(rootfs.path().join("etc/ssl")).unwrap();
        std::os::unix::fs::symlink("/etc/pki/tls/certs", rootfs.path().join("etc/ssl/certs"))
            .unwrap();
        let root = Rootfs::open(rootfs.path()).unwrap();

        root.create_dir_all(Path::new("etc/ssl/certs")).unwrap();
        write!(
            root.create(Path::new("etc/ssl/certs/ca.pem")).unwrap(),
            "PEM"
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(rootfs.path().join("etc/pki/tls/certs/ca.pem")).unwrap(),
            "PEM"
        );
    }

    /// Opening a FIFO for writing blocks until a reader shows up, which would
    /// hang the session before boot.
    #[test]
    fn create_refuses_a_fifo_without_waiting() {
        let rootfs = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(rootfs.path().join("policy"))
            .status()
            .unwrap();
        assert!(status.success());
        let root = Rootfs::open(rootfs.path()).unwrap();

        assert!(root.create(Path::new("policy")).is_err());
    }

    #[test]
    fn create_dir_all_refuses_parent_components() {
        let rootfs = tempfile::tempdir().unwrap();
        let root = Rootfs::open(rootfs.path()).unwrap();

        let err = root.create_dir_all(Path::new("etc/../..")).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
