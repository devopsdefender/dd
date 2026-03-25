use flate2::read::GzDecoder;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const TAR_BLOCK_SIZE: usize = 512;

pub fn prepare_rootfs_dir(rootfs: &Path) -> Result<(), String> {
    if rootfs.exists() {
        fs::remove_dir_all(rootfs)
            .map_err(|e| format!("remove existing rootfs {}: {e}", rootfs.display()))?;
    }

    fs::create_dir_all(rootfs).map_err(|e| format!("create rootfs {}: {e}", rootfs.display()))
}

pub fn unpack_layers<'a, I>(rootfs: &Path, layers: I) -> Result<(), String>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    for layer in layers {
        unpack_layer(rootfs, layer)?;
    }

    Ok(())
}

fn unpack_layer(rootfs: &Path, layer_bytes: &[u8]) -> Result<(), String> {
    let mut archive = Vec::new();
    GzDecoder::new(layer_bytes)
        .read_to_end(&mut archive)
        .map_err(|e| format!("decompress layer: {e}"))?;

    let mut offset = 0usize;
    while offset + TAR_BLOCK_SIZE <= archive.len() {
        let header = &archive[offset..offset + TAR_BLOCK_SIZE];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }

        let entry = TarEntry::parse(header)?;
        let data_start = offset + TAR_BLOCK_SIZE;
        let data_end = data_start
            .checked_add(entry.size as usize)
            .ok_or_else(|| format!("layer entry {} size overflow", entry.path.display()))?;
        if data_end > archive.len() {
            return Err(format!(
                "layer entry {} exceeds archive bounds",
                entry.path.display()
            ));
        }

        if !handle_whiteout(rootfs, &entry.path)? {
            unpack_entry(rootfs, &entry, &archive[data_start..data_end])?;
        }

        let data_blocks = (entry.size as usize).div_ceil(TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
        offset = data_start + data_blocks;
    }

    Ok(())
}

fn unpack_entry(rootfs: &Path, entry: &TarEntry, data: &[u8]) -> Result<(), String> {
    let destination = rootfs.join(&entry.path);
    let parent = destination
        .parent()
        .ok_or_else(|| format!("missing parent directory for {}", destination.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("create parent directory {}: {e}", parent.display()))?;

    match entry.kind {
        TarEntryKind::Regular => {
            remove_path_if_exists(&destination)?;
            fs::write(&destination, data)
                .map_err(|e| format!("write file {}: {e}", destination.display()))?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(entry.mode))
                .map_err(|e| format!("set permissions on {}: {e}", destination.display()))?;
        }
        TarEntryKind::Directory => {
            fs::create_dir_all(&destination)
                .map_err(|e| format!("create directory {}: {e}", destination.display()))?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(entry.mode))
                .map_err(|e| format!("set permissions on {}: {e}", destination.display()))?;
        }
        TarEntryKind::Symlink => {
            let target = entry
                .link_name
                .as_ref()
                .ok_or_else(|| format!("symlink {} missing target", entry.path.display()))?;
            remove_path_if_exists(&destination)?;
            symlink(target, &destination).map_err(|e| {
                format!(
                    "create symlink {} -> {}: {e}",
                    destination.display(),
                    target.display()
                )
            })?;
        }
        TarEntryKind::HardLink => {
            let target = entry
                .link_name
                .as_ref()
                .ok_or_else(|| format!("hard link {} missing target", entry.path.display()))?;
            let source = rootfs.join(target);
            remove_path_if_exists(&destination)?;
            fs::hard_link(&source, &destination).map_err(|e| {
                format!(
                    "create hard link {} -> {}: {e}",
                    destination.display(),
                    source.display()
                )
            })?;
        }
        TarEntryKind::Unsupported(kind) => {
            return Err(format!(
                "unsupported tar entry type {kind:?} for {}",
                entry.path.display()
            ))
        }
    }

    Ok(())
}

fn handle_whiteout(rootfs: &Path, rel_path: &Path) -> Result<bool, String> {
    let file_name = rel_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("invalid whiteout path {}", rel_path.display()))?;

    if file_name == ".wh..wh..opq" {
        let dir = rootfs.join(rel_path.parent().unwrap_or_else(|| Path::new("")));
        clear_directory(&dir)?;
        return Ok(true);
    }

    let Some(target_name) = file_name.strip_prefix(".wh.") else {
        return Ok(false);
    };

    let parent = rel_path.parent().unwrap_or_else(|| Path::new(""));
    let target = rootfs.join(parent).join(target_name);
    remove_path_if_exists(&target)?;
    Ok(true)
}

fn clear_directory(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }

    for child in fs::read_dir(dir).map_err(|e| format!("read directory {}: {e}", dir.display()))? {
        let child = child.map_err(|e| format!("read directory entry in {}: {e}", dir.display()))?;
        remove_path_if_exists(&child.path())?;
    }

    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(()),
    };

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).map_err(|e| format!("remove directory {}: {e}", path.display()))
    } else {
        fs::remove_file(path).map_err(|e| format!("remove file {}: {e}", path.display()))
    }
}

#[derive(Debug)]
struct TarEntry {
    path: PathBuf,
    link_name: Option<PathBuf>,
    size: u64,
    mode: u32,
    kind: TarEntryKind,
}

#[derive(Debug)]
enum TarEntryKind {
    Regular,
    Directory,
    Symlink,
    HardLink,
    Unsupported(u8),
}

impl TarEntry {
    fn parse(header: &[u8]) -> Result<Self, String> {
        let path = sanitize_relative_path(&join_tar_path(
            parse_tar_string(&header[0..100])?,
            parse_tar_string(&header[345..500])?,
        ))?;
        let mode = parse_octal(&header[100..108])? as u32;
        let size = parse_octal(&header[124..136])?;
        let kind = match header[156] {
            0 | b'0' => TarEntryKind::Regular,
            b'5' => TarEntryKind::Directory,
            b'2' => TarEntryKind::Symlink,
            b'1' => TarEntryKind::HardLink,
            other => TarEntryKind::Unsupported(other),
        };
        let link_name_raw = parse_tar_string(&header[157..257])?;
        let link_name = if link_name_raw.is_empty() {
            None
        } else {
            Some(sanitize_relative_path(&PathBuf::from(link_name_raw))?)
        };

        Ok(Self {
            path,
            link_name,
            size,
            mode,
            kind,
        })
    }
}

fn parse_tar_string(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value =
        std::str::from_utf8(&bytes[..end]).map_err(|e| format!("invalid tar header: {e}"))?;
    Ok(value.trim().to_string())
}

fn parse_octal(bytes: &[u8]) -> Result<u64, String> {
    let value = parse_tar_string(bytes)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }

    u64::from_str_radix(trimmed, 8).map_err(|e| format!("invalid tar octal value {trimmed:?}: {e}"))
}

fn join_tar_path(name: String, prefix: String) -> PathBuf {
    if prefix.is_empty() {
        PathBuf::from(name)
    } else {
        PathBuf::from(prefix).join(name)
    }
}

fn sanitize_relative_path(path: &Path) -> Result<PathBuf, String> {
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => sanitized.push(value),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(format!("refusing to unpack path {}", path.display()))
            }
        }
    }

    Ok(sanitized)
}

#[cfg(test)]
mod tests {
    use super::unpack_layers;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn whiteout_removes_file_from_lower_layer() {
        let temp = temp_dir("whiteout_removes_file_from_lower_layer");
        let rootfs = temp.join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let base = tar_layer(&[TarEntrySpec::file("etc/config", b"hello")]);
        let whiteout = tar_layer(&[TarEntrySpec::file("etc/.wh.config", b"")]);

        unpack_layers(&rootfs, [base.as_slice(), whiteout.as_slice()]).unwrap();
        assert!(!rootfs.join("etc/config").exists());
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn opaque_whiteout_clears_directory_contents() {
        let temp = temp_dir("opaque_whiteout_clears_directory_contents");
        let rootfs = temp.join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let base = tar_layer(&[
            TarEntrySpec::file("app/one.txt", b"one"),
            TarEntrySpec::file("app/two.txt", b"two"),
        ]);
        let whiteout = tar_layer(&[TarEntrySpec::file("app/.wh..wh..opq", b"")]);

        unpack_layers(&rootfs, [base.as_slice(), whiteout.as_slice()]).unwrap();
        assert!(Path::new(&rootfs.join("app")).exists());
        assert_eq!(fs::read_dir(rootfs.join("app")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(temp);
    }

    struct TarEntrySpec<'a> {
        path: &'a str,
        data: &'a [u8],
        kind: u8,
    }

    impl<'a> TarEntrySpec<'a> {
        fn file(path: &'a str, data: &'a [u8]) -> Self {
            Self {
                path,
                data,
                kind: b'0',
            }
        }
    }

    fn tar_layer(entries: &[TarEntrySpec<'_>]) -> Vec<u8> {
        let mut archive = Vec::new();

        for entry in entries {
            archive.extend(make_header(entry.path, entry.data.len() as u64, entry.kind));
            archive.extend(entry.data);

            let padding = (512 - (entry.data.len() % 512)) % 512;
            archive.extend(vec![0u8; padding]);
        }

        archive.extend(vec![0u8; 1024]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&archive).unwrap();
        encoder.finish().unwrap()
    }

    fn make_header(path: &str, size: u64, kind: u8) -> [u8; 512] {
        let mut header = [0u8; 512];
        write_bytes(&mut header[0..100], path.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        write_bytes(&mut header[257..263], b"ustar\0");
        write_bytes(&mut header[263..265], b"00");

        let checksum: u32 = header.iter().map(|byte| *byte as u32).sum();
        write_octal(&mut header[148..156], checksum as u64);
        header
    }

    fn write_bytes(dst: &mut [u8], src: &[u8]) {
        let len = src.len().min(dst.len());
        dst[..len].copy_from_slice(&src[..len]);
    }

    fn write_octal(dst: &mut [u8], value: u64) {
        let width = dst.len() - 1;
        let encoded = format!("{value:0width$o}\0");
        write_bytes(dst, encoded.as_bytes());
    }

    fn temp_dir(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("dd-agent-{test_name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
