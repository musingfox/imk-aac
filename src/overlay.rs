//! immurok's overlay shows the gated command line, so imk runs `Bitwarden
//! <text>` from a private PATH where `Bitwarden` is a link to /usr/bin/true,
//! and the overlay reads as a sentence instead of a path.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use tokio::process::Command;
use tracing::warn;

const SHOWN: &str = "Bitwarden";
const TRUE: &str = "/usr/bin/true";
const DIR: &str = "Library/Application Support/imk-aac/bin";

/// `imk run --agent` gating a no-op whose command line is `Bitwarden <text>`,
/// or `/usr/bin/true <text>` when the private PATH cannot be trusted.
pub fn imk_run(imk: &str, text: &str) -> Command {
    let mut cmd = Command::new(imk);
    match ready() {
        Ok(dir) => {
            cmd.env("PATH", dir)
                .args(["run", "--agent", "--", SHOWN, text]);
        }
        Err(e) => {
            warn!("private PATH unusable ({e}); overlay shows {TRUE}");
            cmd.args(["run", "--agent", "--", TRUE, text]);
        }
    }
    cmd
}

fn ready() -> Result<PathBuf, String> {
    let dir = dirs::home_dir().ok_or("no home directory")?.join(DIR);
    prepare(&dir).map_err(|e| format!("cannot set up {}: {e}", dir.display()))?;
    // SAFETY: getuid has no preconditions and cannot fail.
    verify(&dir, unsafe { libc::getuid() })?;
    Ok(dir)
}

/// Creates what is missing and never repairs what exists: anything wrong is
/// left for verify to refuse.
fn prepare(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let link = dir.join(SHOWN);
    match fs::symlink_metadata(&link) {
        Err(e) if e.kind() == ErrorKind::NotFound => std::os::unix::fs::symlink(TRUE, &link),
        other => other.map(|_| ()),
    }
}

/// Checked before every use: imk resolves `Bitwarden` through this PATH, so
/// only this user may be able to change what it points at.
fn verify(dir: &Path, uid: u32) -> Result<(), String> {
    let meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != uid {
        return Err(format!("{} is owned by uid {}", dir.display(), meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{} is writable by group or others", dir.display()));
    }
    let link = dir.join(SHOWN);
    let meta = fs::symlink_metadata(&link).map_err(|e| e.to_string())?;
    if !meta.file_type().is_symlink() {
        return Err(format!("{} is not a symlink", link.display()));
    }
    let target = fs::read_link(&link).map_err(|e| e.to_string())?;
    if target != Path::new(TRUE) {
        return Err(format!("{} points at {}", link.display(), target.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("imk-aac-overlay-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn uid() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    #[test]
    fn prepared_dir_passes() {
        let dir = scratch("good");
        prepare(&dir).unwrap();
        assert_eq!(fs::symlink_metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(verify(&dir, uid()), Ok(()));
        prepare(&dir).unwrap();
        assert_eq!(verify(&dir, uid()), Ok(()));
        assert!(verify(&dir, uid() + 1).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn link_to_another_target_fails() {
        let dir = scratch("target");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        std::os::unix::fs::symlink("/bin/sh", dir.join(SHOWN)).unwrap();
        prepare(&dir).unwrap();
        assert!(
            verify(&dir, uid())
                .unwrap_err()
                .contains("points at /bin/sh")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn regular_file_fails() {
        let dir = scratch("file");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        fs::write(dir.join(SHOWN), "#!/bin/sh\n").unwrap();
        prepare(&dir).unwrap();
        assert!(verify(&dir, uid()).unwrap_err().contains("not a symlink"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn group_writable_dir_fails() {
        let dir = scratch("perm");
        prepare(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(verify(&dir, uid()).unwrap_err().contains("writable"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
