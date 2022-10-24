#[cfg(target_os = "macos")]
mod codesign;

#[cfg(target_os = "macos")]
mod error;

#[cfg(target_os = "macos")]
mod main {

    use std::{
        fs::Permissions,
        os::{macos::fs::MetadataExt, unix::prelude::PermissionsExt},
        path::Path,
    };

    use object::{
        macho::{FatHeader, MachHeader32, MachHeader64, CPU_TYPE_X86_64},
        read::macho::{FatArch, MachHeader},
        Architecture, Endianness, FileKind,
    };

    use crate::error::{Result, SipError};

    fn is_fat_x64_arch(arch: &&impl FatArch) -> bool {
        matches!(arch.architecture(), Architecture::X86_64)
    }

    struct BinaryInfo {
        offset: usize,
        size: usize,
    }

    impl BinaryInfo {
        fn new(offset: usize, size: usize) -> Self {
            Self { offset, size }
        }

        /// Gets x64 binary offset from a Mach-O fat binary or returns 0 if is x64 macho binary.
        fn from_object_bytes(bytes: &[u8]) -> Result<Self> {
            match FileKind::parse(bytes)? {
                FileKind::MachO32 => {
                    let header: &MachHeader32<Endianness> =
                        MachHeader::parse(bytes, 0).map_err(|_| {
                            SipError::UnsupportedFileFormat(
                                "MachO 32 file parsing failed".to_string(),
                            )
                        })?;
                    if header.cputype(Endianness::default()) == CPU_TYPE_X86_64 {
                        Ok(Self::new(0, bytes.len()))
                    } else {
                        Err(SipError::NoX64Arch)
                    }
                }
                FileKind::MachO64 => {
                    let header: &MachHeader64<Endianness> =
                        MachHeader::parse(bytes, 0).map_err(|_| {
                            SipError::UnsupportedFileFormat(
                                "MachO 64 file parsing failed".to_string(),
                            )
                        })?;
                    if header.cputype(Endianness::default()) == CPU_TYPE_X86_64 {
                        Ok(Self::new(0, bytes.len()))
                    } else {
                        Err(SipError::NoX64Arch)
                    }
                }
                FileKind::MachOFat32 => FatHeader::parse_arch32(bytes)
                    .map_err(|_| SipError::UnsupportedFileFormat("FatMach-O 32-bit".to_string()))?
                    .iter()
                    .find(is_fat_x64_arch)
                    .map(|arch| Self::new(arch.offset() as usize, arch.size() as usize))
                    .ok_or(SipError::NoX64Arch),
                FileKind::MachOFat64 => FatHeader::parse_arch64(bytes)
                    .map_err(|_| SipError::UnsupportedFileFormat("Mach-O 32-bit".to_string()))?
                    .iter()
                    .find(is_fat_x64_arch)
                    .map(|arch| Self::new(arch.offset() as usize, arch.size() as usize))
                    .ok_or(SipError::NoX64Arch),
                other => Err(SipError::UnsupportedFileFormat(format!("{:?}", other))),
            }
        }
    }

    /// Patches a binary to disable SIP.
    /// Right now it extracts x64 binary from fat/MachO binary and patches it.
    fn patch_binary<P: AsRef<Path>, K: AsRef<Path>>(path: P, output: K) -> Result<()> {
        let data = std::fs::read(path.as_ref())?;
        let binary_info = BinaryInfo::from_object_bytes(&data)?;

        let x64_binary = &data[binary_info.offset..binary_info.offset + binary_info.size];
        std::fs::write(output.as_ref(), x64_binary)?;
        std::fs::set_permissions(output.as_ref(), Permissions::from_mode(0o755))?;
        codesign::sign(output)
    }

    const SF_RESTRICTED: u32 = 0x00080000; // entitlement required for writing, from stat.h (macos)

    /// Checks the SF_RESTRICTED flags on a file (there might be a better check, feel free to
    /// suggest)
    fn is_sip<P: AsRef<Path>>(path: P) -> Result<bool> {
        let metadata = std::fs::metadata(path)?;
        Ok((metadata.st_flags() & SF_RESTRICTED) > 0)
    }

    pub fn sip_patch(binary_path: &mut String) -> Result<()> {
        let complete_path = which(&binary_path)?;

        if !is_sip(&complete_path)? {
            return Ok(());
        }

        // Strip root path from binary path, as when joined it will clear the previous.
        let output = temp_dir()
            .join("mirrord-bin")
            .join(&complete_path.strip_prefix("/")?);

        // Patched version already exists
        if output.exists() {
            trace!("exists {:?}", &output);
            *binary_path = output
                .to_str()
                .ok_or_else(|| anyhow!("Failed to convert path to string"))?
                .to_string();
            return Ok(());
        }

        std::fs::create_dir_all(
            output
                .parent()
                .ok_or_else(|| SipError::UnlikelyError("Failed to get parent directory"))?,
        )?;
        if let Ok(()) = patch_binary(&complete_path, &output) {
            *binary_path = output
                .to_str()
                .ok_or_else(|| anyhow!("Failed to convert path to string"))?
                .to_string();
        }
        trace!("patched successfuly {:?}", &output);
        Ok(())
    }

    #[cfg(test)]
    mod tests {

        use std::io::Write;

        use super::*;

        #[test]
        fn is_sip_true() {
            assert!(is_sip("/bin/ls").unwrap());
        }

        #[test]
        fn is_sip_false() {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            let data = std::fs::read("/bin/ls").unwrap();
            f.write(&data).unwrap();
            f.flush().unwrap();
            assert!(!is_sip(f.path().to_str().unwrap()).unwrap());
        }

        #[test]
        fn is_sip_notfound() {
            let err = is_sip("/donald/duck/was/a/duck/not/a/quack/a/duck").unwrap_err();
            assert!(err.to_string().contains("No such file or directory"));
        }

        #[test]
        fn patch_binary_fat() {
            let path = "/bin/ls";
            let output = "/tmp/ls_mirrord_test";
            patch_binary(path, output).unwrap();
            assert!(!is_sip(output).unwrap());
            // Check DYLD_* features work on it:
            let output = std::process::Command::new(output)
                .env("DYLD_PRINT_LIBRARIES", "1")
                .output()
                .unwrap();
            assert!(String::from_utf8_lossy(&output.stderr).contains("libsystem_kernel.dylib"));
        }
    }
}

#[cfg(target_os = "macos")]
pub use main::*;
