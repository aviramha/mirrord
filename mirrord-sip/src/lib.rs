// use std::{fs::File, io::{Read, Cursor}};

// use mach_object::{MachCommand, MachHeader, OFile};

// fn is_sip_macho(header: &MachHeader, commands: &Vec<MachCommand>) -> Result<bool> {
//     commands.iter().any(| command | {
//         command.command()
//     })
// }

use std::borrow::BorrowMut;

// /// To know if binary is SIP protected for sure, it's in either cases (based on dyld-852.2 code):
// /// 1. has __RESTRICT segment -- skipped, didn't see it in the wild
// /// 2. has setuid/setgid bit set - skipped for now
// /// 3. code is signed with entitlements.
// pub(crate) fn is_sip(path: &str) -> Result<bool> {
//     let mut f = File::open(path)?;
//     let mut buf = Vec::new();
//     let size = f.read_to_end(&mut buf).unwrap();
//     let mut cur = Cursor::new(&buf[..size]);
//     match OFile::parse(&mut cur) {
//         Ok(OFile::MachFile { header, commands }) => is_sip_macho(&header, &commands),
//         Ok(OFile::FatFile { magic: _, files }) => Ok(files.iter().any(|(_, in_file)| match in_file {
//             OFile::MachFile { header, commands } => {
//                 is_sip_macho(&header, &commands).unwrap_or(false)
//             }
//             _ => false,
//         })),
//         _ => Ok(false),
//     }
// }
use object::{File, read::macho::FatArch, macho::{FatHeader, CPU_TYPE_ARM64, CPU_SUBTYPE_PTRAUTH_ABI, FatArch64}, BigEndian};
use anyhow::Result;

pub(crate) fn patch_binary(path: &str, output: &str) -> Result<()> {
    let data = std::fs::read(path)?;
    let obj = FatHeader::parse_arch64(&*data)?;
    for mut file in obj {
        let cpu_sub_type = file.cpusubtype.get(BigEndian);
        if file.cputype.get(BigEndian) == CPU_TYPE_ARM64 && (cpu_sub_type & CPU_SUBTYPE_PTRAUTH_ABI != 0) {
            let file_bytes = object::pod::bytes_of(file);
            let (res, _) = object::pod::from_bytes_mut::<FatArch64>(file_bytes.as_mut()).unwrap();
            res.cpusubtype.set(BigEndian, cpu_sub_type ^ CPU_SUBTYPE_PTRAUTH_ABI);
        }
    }
    Ok(())
}