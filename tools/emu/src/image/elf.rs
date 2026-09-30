// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Just enough ELF32 (little-endian) to place an RP2350 image in flash and name
//! addresses: PT_LOAD segments by physical (load) address, and the symbol table.

pub struct Segment {
    pub paddr: u32,
    pub data: Vec<u8>,
}

pub struct Symbol {
    pub name: String,
    pub value: u32,
    pub size: u32,
}

pub struct Elf {
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
}

fn u16_at(b: &[u8], o: usize) -> Result<u16, String> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("ELF truncated at {o:#x}"))
}

fn u32_at(b: &[u8], o: usize) -> Result<u32, String> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("ELF truncated at {o:#x}"))
}

impl Elf {
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        if b.get(0..6) != Some(&[0x7F, b'E', b'L', b'F', 1, 1]) {
            return Err("not a little-endian ELF32 file".into());
        }
        let phoff = u32_at(b, 0x1C)? as usize;
        let shoff = u32_at(b, 0x20)? as usize;
        let phentsize = u16_at(b, 0x2A)? as usize;
        let phnum = u16_at(b, 0x2C)? as usize;
        let shentsize = u16_at(b, 0x2E)? as usize;
        let shnum = u16_at(b, 0x30)? as usize;

        let mut segments = Vec::new();
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            const PT_LOAD: u32 = 1;
            if u32_at(b, ph)? != PT_LOAD {
                continue;
            }
            let offset = u32_at(b, ph + 4)? as usize;
            let paddr = u32_at(b, ph + 12)?;
            let filesz = u32_at(b, ph + 16)? as usize;
            if filesz == 0 {
                continue;
            }
            let data = b
                .get(offset..offset + filesz)
                .ok_or("PT_LOAD segment past end of file")?
                .to_vec();
            segments.push(Segment { paddr, data });
        }

        let mut symbols = Vec::new();
        for i in 0..shnum {
            let sh = shoff + i * shentsize;
            const SHT_SYMTAB: u32 = 2;
            if u32_at(b, sh + 4)? != SHT_SYMTAB {
                continue;
            }
            let off = u32_at(b, sh + 16)? as usize;
            let size = u32_at(b, sh + 20)? as usize;
            let link = u32_at(b, sh + 24)? as usize;
            let strsh = shoff + link * shentsize;
            let stroff = u32_at(b, strsh + 16)? as usize;
            for s in (off..off + size).step_by(16) {
                let name_off = u32_at(b, s)? as usize;
                let value = u32_at(b, s + 4)?;
                let size = u32_at(b, s + 8)?;
                let start = stroff + name_off;
                let end = b
                    .get(start..)
                    .and_then(|rest| rest.iter().position(|&c| c == 0))
                    .map(|n| start + n)
                    .ok_or("unterminated symbol name")?;
                let name = String::from_utf8_lossy(&b[start..end]).into_owned();
                if !name.is_empty() {
                    symbols.push(Symbol { name, value, size });
                }
            }
        }
        Ok(Self { segments, symbols })
    }

    /// First symbol whose (mangled) name contains every fragment.
    pub fn symbol(&self, fragments: &[&str]) -> Option<&Symbol> {
        self.symbols
            .iter()
            .find(|s| fragments.iter().all(|f| s.name.contains(f)))
    }

    /// The function symbol covering `addr` (Thumb bit ignored), if any.
    pub fn function_at(&self, addr: u32) -> Option<&Symbol> {
        let a = addr & !1;
        self.symbols
            .iter()
            .filter(|s| s.size > 0 && (s.value & !1) <= a && a < (s.value & !1) + s.size)
            .min_by_key(|s| s.size)
    }
}

#[cfg(test)]
#[path = "elf_tests.rs"]
mod tests;
