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
    // The wire path is host independent, so a drive prefix (`C:`, `C:/…`) or a UNC
    // prefix is a client bug on any server. Left to `Path::components` it is a prefix
    // on Windows but a plain (oddly named) directory on Unix — refuse it everywhere.
    // `a:b.txt` stays legal on Unix: it only looks like a drive when a separator or
    // the end of the path follows the colon.
    let head = rel.as_bytes();
    let drive = head.len() >= 2
        && head[0].is_ascii_alphabetic()
        && head[1] == b':'
        && (head.len() == 2 || head[2] == b'/');
    if drive || rel.starts_with("//") {
        return Err(format!("illegal path component in {rel:?}"));
    }
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

/// Streamed sha256 of a file, base64url encoded. Used to verify a transfer end to end.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(crate::identity::b64e(&hasher.finalize()))
}

/// Recursively list files under `base`, paths relative to `base` with `/` separators.
/// Symlinks are skipped: simpler than proving every link stays inside the root.
pub fn walk(base: &Path) -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    let md = std::fs::symlink_metadata(base)?;
    if md.is_file() {
        out.push(Entry { path: rel_string(base_parent(base), base), size: md.len(), mtime: mtime(&md), dir: false });
        return Ok(out);
    }
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for item in std::fs::read_dir(&dir)? {
            let item = item?;
            let ft = item.file_type()?;
            if ft.is_symlink() {
                continue;
            }
            let p = item.path();
            if ft.is_dir() {
                // kept so that empty directories survive a sync
                out.push(Entry {
                    path: rel_string(base, &p),
                    size: 0,
                    mtime: mtime(&item.metadata()?),
                    dir: true,
                });
                stack.push(p);
            } else if ft.is_file() {
                if is_part(item.file_name().as_os_str()) {
                    continue;
                }
                let md = item.metadata()?;
                out.push(Entry { path: rel_string(base, &p), size: md.len(), mtime: mtime(&md), dir: false });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn base_parent(p: &Path) -> &Path {
    p.parent().unwrap_or(Path::new(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_escapes() {
        let root = std::env::temp_dir().join("dtu-guard-root");
        std::fs::create_dir_all(&root).unwrap();
        for bad in ["../x", "a/../../b", "C:\\Windows\\system32", "/etc/passwd", "..", "\\\\server\\share"] {
            assert!(resolve(&root, bad).is_err(), "should reject {bad:?}");
        }
        assert!(resolve(&root, "a/b.txt").is_ok());
        assert!(resolve(&root, "a//b.txt").is_ok());
        assert!(resolve(&root, "./a/b.txt").is_ok());
        assert_eq!(resolve(&root, "").unwrap(), root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_lists_relative_paths() {
        let root = std::env::temp_dir().join(format!("dtu-walk-{}", crate::identity::random_id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("sub/b.txt"), b"bb").unwrap();
        let e = walk(&root).unwrap();
        let got: Vec<(&str, u64)> = e.iter().filter(|x| !x.dir).map(|x| (x.path.as_str(), x.size)).collect();
        assert_eq!(got, vec![("a.txt", 3), ("sub/b.txt", 2)]);
        assert_eq!(e.iter().filter(|x| x.dir).count(), 1, "the sub directory should be reported");
        let _ = std::fs::remove_dir_all(root);
    }
}
