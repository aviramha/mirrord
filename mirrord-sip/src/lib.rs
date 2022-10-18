// use std::{fs::File, io::{Read, Cursor}};

// use mach_object::{MachCommand, MachHeader, OFile};

// fn is_sip_macho(header: &MachHeader, commands: &Vec<MachCommand>) -> Result<bool> {
//     commands.iter().any(| command | {
//         command.command()
//     })
// }


use std::ops::Range;

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
// use object::{File, read::macho::FatArch, macho::{FatHeader, CPU_TYPE_ARM64, CPU_SUBTYPE_PTRAUTH_ABI, FatArch64}, BigEndian};
use anyhow::{anyhow, Result};
use object::{BigEndian, macho::{FatHeader, FAT_MAGIC, FatArch64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64_32, FatArch32, CPU_SUBTYPE_PTRAUTH_ABI, MachHeader64}, LittleEndian};

pub fn patch_binary(path: &str, output: &str) -> Result<()> {
    let mut data = std::fs::read(path)?;
    let (header, _): (&FatHeader,_) = object::from_bytes(&data[..std::mem::size_of::<FatHeader>()]).unwrap();
    let magic = header.magic.get(BigEndian);
    if magic != FAT_MAGIC {
        return Err(anyhow!("invalid magic {magic:?}"));
    }
    let arch_count = header.nfat_arch.get(BigEndian) as usize;
    let archs_range = Range {
        start: std::mem::size_of::<FatHeader>(),
        end: std::mem::size_of::<FatHeader>() + arch_count * std::mem::size_of::<FatArch32>(),
    };
    let (archs, _) : (&mut [FatArch32], _) = object::slice_from_bytes_mut(&mut data[archs_range], arch_count).unwrap();
    let mut arch_offset = 0;
    let mut arch_size = 0;
    for arch in archs {
        let cpu_type = arch.cputype.get(BigEndian);
        let cpu_subtype = arch.cpusubtype.get(BigEndian);
        println!("test: {:?}", cpu_type & CPU_TYPE_ARM64);
        if cpu_type == CPU_TYPE_ARM64 && (cpu_subtype & CPU_SUBTYPE_ARM64E) > 0 {
            arch.cpusubtype.set(BigEndian, cpu_subtype ^ CPU_SUBTYPE_ARM64E);
            arch_offset = arch.offset.get(BigEndian) as usize;
            arch_size = arch.size.get(BigEndian) as usize;
            println!("patch1");
        } else {
            println!("{cpu_type:?} {cpu_subtype:?}");
        }

    }
    let range = Range {
        start: arch_offset,
        end: arch_offset + arch_size,
    };
    let (arch_header, _): (&mut MachHeader64<LittleEndian>, _) = object::from_bytes_mut(&mut data[range]).unwrap();
    let cpu_type = arch_header.cputype.get(LittleEndian);
    let cpu_subtype = arch_header.cpusubtype.get(LittleEndian);
    println!("magic {:?}", arch_header.magic.get(BigEndian));
    if cpu_type == CPU_TYPE_ARM64 && (cpu_subtype & CPU_SUBTYPE_ARM64E) > 0 {
        println!("patch2");
        arch_header.cpusubtype.set(LittleEndian, cpu_subtype ^ CPU_SUBTYPE_ARM64E);
    } else {
        println!("{cpu_type:?} {cpu_subtype:?}");
    }
    std::fs::write(output, data).unwrap();
    Ok(())
}

// pub fn patch_binary(path: &str, _output: &str) -> Result<()> {
//     let data = std::fs::read(path)?;
//     let arch = object::macho::FatHeader::parse_arch32(&*data).unwrap();

//     Ok(())
// }
