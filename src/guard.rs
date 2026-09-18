//! Path safety and directory walking. Every remote path goes through `resolve`.

use std::io;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::proto::Entry;

/// In-progress transfers live next to their target under this suffix, so a reader
/// never sees a half-written file and an interrupted transfer is still resumable.
pub const PART_SUFFIX: &str = ".dtu-part";

pub fn part_path(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(PART_SUFFIX);
    PathBuf::from(s)
}

fn is_part(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().ends_with(PART_SUFFIX)
}

/// Map a wire path (forward slashes, relative) to a real path guaranteed under `root`.
pub fn resolve(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let rel = rel.replace('\\', "/");
    let mut out = PathBuf::new();
    for c in Path::new(&rel).components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => return Err(format!("illegal path component in {rel:?}")),
        }
    }
    if out.as_os_str().is_empty() {
        return Ok(root.to_path_buf());
    }
    // The staging suffix is protocol-reserved: a file that ends with it could never be
    // listed or landed, so refuse it loudly instead of silently hiding it.
    if out.to_string_lossy().ends_with(PART_SUFFIX) {
        return Err(format!("path uses the reserved suffix {PART_SUFFIX}: {rel:?}"));
    }
    let joined = root.join(&out);
    if !joined.starts_with(root) {
        return Err(format!("path escapes root: {rel:?}"));
    }
    // Symlink escape: only checkable once the target exists.
    if let (Ok(croot), Ok(creal)) = (root.canonicalize(), joined.canonicalize()) {
        if !creal.starts_with(&croot) {
            return Err(format!("path escapes root via link: {rel:?}"));
        }
    }
    Ok(joined)
}

pub fn rel_string(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .unwrap_or(p)
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn mtime(md: &std::fs::Metadata) -> u64 {
    mtime_of(md.modified().ok())
}

/// Human-facing path: the canonical form on Windows carries a `\\?\` prefix.
pub fn for_display(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

pub fn mtime_of(t: Option<std::time::SystemTime>) -> u64 {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)
}

