//! COMPOUND_TEXT 编解码。编码只输出 UTF-8 段；解码按 ISO-2022 状态机处理
//! GL/GR 字符集指派（ASCII、ISO-8859 系列、GB2312、JIS X 0208、KS C 5601）
//! 和 UTF-8 段，遇到无法识别的内容用 U+FFFD 替代，永不返回 Err。

#![no_std]
// CText::len 是上游 0.3 公开 API，保持原样。
#![allow(clippy::len_without_is_empty)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "std")]
use std::io::{self, Write};

const UTF8_START: &[u8] = &[0x1B, 0x25, 0x47];
const UTF8_END: &[u8] = &[0x1B, 0x25, 0x40];

/// Wrapper for reduce allocation
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct CText<'s> {
    utf8: &'s str,
}

impl<'s> fmt::Debug for CText<'s> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.utf8)
    }
}

impl<'s> fmt::Display for CText<'s> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.utf8)
    }
}

impl<'s> CText<'s> {
    pub const fn new(utf8: &'s str) -> Self {
        Self { utf8 }
    }

    pub const fn len(self) -> usize {
        self.utf8.len() + UTF8_START.len() + UTF8_END.len()
    }

    #[cfg(feature = "std")]
    pub fn write(self, mut out: impl Write) -> io::Result<usize> {
        let mut writed = 0;
        writed += out.write(UTF8_START)?;
        writed += out.write(self.utf8.as_bytes())?;
        writed += out.write(UTF8_END)?;
        Ok(writed)
    }
}

/// Encoding utf8 to COMPOUND_TEXT with utf8 escape
pub fn utf8_to_compound_text(text: &str) -> Vec<u8> {
    let mut ret = Vec::with_capacity(text.len() + 6);
    ret.extend_from_slice(UTF8_START);
    ret.extend_from_slice(text.as_bytes());
    ret.extend_from_slice(UTF8_END);
    ret
}

#[derive(Debug, Clone)]
pub enum DecodeError {
    InvalidEncoding,
    UnsupportedEncoding,
    Utf8Error(alloc::string::FromUtf8Error),
}

impl From<alloc::string::FromUtf8Error> for DecodeError {
    fn from(err: alloc::string::FromUtf8Error) -> Self {
        DecodeError::Utf8Error(err)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => write!(f, "Invalid compound text"),
            Self::UnsupportedEncoding => write!(f, "This encoding is not supported yet"),
            Self::Utf8Error(e) => write!(f, "Not a valid utf8 {}", e),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Charset {
    Ascii,
    Latin1,
    /// 96 字符单字节集（ISO-8859-x 右半部），字节按原值交给对应编码解码。
    Single(&'static encoding_rs::Encoding),
    /// 94x94 双字节集，字节 |0x80 后按 EUC 形式解码。
    Double(&'static encoding_rs::Encoding),
    Unknown,
}

fn single_byte_set(final_byte: u8) -> Charset {
    use encoding_rs::*;
    match final_byte {
        b'A' => Charset::Latin1,
        b'B' => Charset::Single(ISO_8859_2),
        b'C' => Charset::Single(ISO_8859_3),
        b'D' => Charset::Single(ISO_8859_4),
        b'F' => Charset::Single(ISO_8859_7),
        b'G' => Charset::Single(ISO_8859_6),
        b'H' => Charset::Single(ISO_8859_8),
        b'L' => Charset::Single(ISO_8859_5),
        b'M' => Charset::Single(WINDOWS_1254),
        b'V' => Charset::Single(ISO_8859_10),
        b'Y' => Charset::Single(ISO_8859_13),
        b'_' => Charset::Single(ISO_8859_14),
        b'b' => Charset::Single(ISO_8859_15),
        b'f' => Charset::Single(ISO_8859_16),
        _ => Charset::Unknown,
    }
}

fn double_byte_set(final_byte: u8) -> Charset {
    match final_byte {
        b'A' => Charset::Double(encoding_rs::GBK),
        b'B' | b'@' => Charset::Double(encoding_rs::EUC_JP),
        b'C' => Charset::Double(encoding_rs::EUC_KR),
        _ => Charset::Unknown,
    }
}

fn flush(out: &mut String, set: Charset, run: &mut Vec<u8>) {
    if run.is_empty() {
        return;
    }
    match set {
        Charset::Ascii | Charset::Latin1 => out.push_str(&encoding_rs::mem::decode_latin1(run)),
        Charset::Single(encoding) | Charset::Double(encoding) => {
            out.push_str(&encoding.decode_without_bom_handling(run).0)
        }
        Charset::Unknown => out.push('\u{FFFD}'),
    }
    run.clear();
}

/// 解码 COMPOUND_TEXT。输入法发来的数据不可信，任何无法识别的转义序列或字节
/// 都以 U+FFFD 替代后继续，保证调用方（zed-xim 对结果 expect）不会 panic。
pub fn compound_text_to_utf8(bytes: &[u8]) -> Result<String, DecodeError> {
    let mut out = String::with_capacity(bytes.len());
    // COMPOUND_TEXT 初始状态：GL = ASCII，GR = ISO-8859-1 右半部。
    let mut gl = Charset::Ascii;
    let mut gr = Charset::Latin1;
    let mut run_set = Charset::Ascii;
    let mut run = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == 0x1b {
            flush(&mut out, run_set, &mut run);
            // 转义序列：ESC，若干中间字节 0x20..=0x2F，一个终止字节 0x30..=0x7E。
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (0x20..=0x2f).contains(&bytes[end]) {
                end += 1;
            }
            let Some(&final_byte) = bytes.get(end) else {
                out.push('\u{FFFD}');
                break;
            };
            match &bytes[start..end] {
                b"%" if final_byte == b'G' => {
                    // UTF-8 段一直延续到 ESC % @ 或文本结尾。
                    let body = &bytes[end + 1..];
                    let len = body
                        .windows(3)
                        .position(|w| w == [0x1b, b'%', b'@'])
                        .unwrap_or(body.len());
                    out.push_str(&String::from_utf8_lossy(&body[..len]));
                    i = end + 1 + (len + 3).min(body.len());
                    continue;
                }
                b"(" => {
                    gl = if matches!(final_byte, b'B' | b'J') {
                        Charset::Ascii
                    } else {
                        Charset::Unknown
                    }
                }
                b"-" => gr = single_byte_set(final_byte),
                b"$" | b"$(" => gl = double_byte_set(final_byte),
                b"$)" => gr = double_byte_set(final_byte),
                _ => out.push('\u{FFFD}'),
            }
            i = end + 1;
            continue;
        }

        // C0 控制字符、空格和 DEL 不属于任何 94/96 字符集，按 ASCII 输出。
        let set = if b < 0x80 {
            if b <= 0x20 || b == 0x7f {
                Charset::Ascii
            } else {
                gl
            }
        } else {
            gr
        };
        if set != run_set {
            flush(&mut out, run_set, &mut run);
            run_set = set;
        }
        run.push(if matches!(set, Charset::Double(_)) {
            b | 0x80
        } else {
            b
        });
        i += 1;
    }
    flush(&mut out, run_set, &mut run);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::compound_text_to_utf8 as decode;

    #[test]
    fn korean() {
        const UTF8: &str = "가나다";
        const COMP: &[u8] = &[
            27, 37, 71, 234, 176, 128, 235, 130, 152, 235, 139, 164, 27, 37, 64,
        ];
        assert_eq!(crate::utf8_to_compound_text(UTF8), COMP);
        assert_eq!(decode(COMP).unwrap(), UTF8);
    }

    #[test]
    fn iso_2022_jp() {
        assert_eq!(decode(&[27, 36, 40, 66, 69, 108, 53, 126]).unwrap(), "東京");
    }

    #[test]
    fn gb2312_gl() {
        const COMP: &[u8] = &[
            0x1b, 0x24, 0x28, 0x41, 0x3a, 0x5c, 0x38, 0x5f, 0x50, 0x4b, 0x48, 0x4f, 0x4a, 0x36,
            0x44, 0x63,
        ];
        assert_eq!(decode(COMP).unwrap(), "很高兴认识你");
    }

    #[test]
    fn gb2312_gl_mixed_ascii() {
        #[rustfmt::skip]
        const COMP: &[u8] = &[
            b'2', b'0', b'2', b'6',
            0x1b, 0x24, 0x28, 0x41, 0x44, 0x6a, // 年
            0x1b, 0x28, 0x42, b'0', b'7',
            0x1b, 0x24, 0x28, 0x41, 0x54, 0x42, // 月
        ];
        assert_eq!(decode(COMP).unwrap(), "2026年07月");
    }

    #[test]
    fn gb2312_gr_interleaved_with_ascii() {
        // Xlib 常见形式：GR 指派 GB2312 后，ASCII 走 GL，不再插入转义。
        const COMP: &[u8] = &[
            0x1b, 0x24, 0x29, 0x41, b'n', b'i', b' ', 0xc4, 0xe3, 0xba, 0xc3,
        ];
        assert_eq!(decode(COMP).unwrap(), "ni 你好");
    }

    #[test]
    fn ibus_preedit_captured_on_ubuntu() {
        // Ubuntu 24.04 ibus-libpinyin 经 XIM 实测发来的预编辑字节。
        // zh_CN.UTF-8：整段 GB2312。
        const ZH: &[u8] = &[
            0x1b, 0x24, 0x28, 0x41, 0x56, 0x50, 0x4e, 0x44, 0x4a, 0x64, 0x48, 0x6b, 0x37, 0x28,
        ];
        assert_eq!(decode(ZH).unwrap(), "中文输入法");
        // en_US.UTF-8：JIS X 0208 与 GB2312 交替（0.3.0 在此 panic）。
        #[rustfmt::skip]
        const EN: &[u8] = &[
            0x1b, 0x24, 0x28, 0x42, 0x43, 0x66, 0x4a, 0x38,
            0x1b, 0x24, 0x28, 0x41, 0x4a, 0x64,
            0x1b, 0x24, 0x28, 0x42, 0x46, 0x7e, 0x4b, 0x21,
        ];
        assert_eq!(decode(EN).unwrap(), "中文输入法");
    }

    #[test]
    fn ks_c_5601() {
        const COMP: &[u8] = &[
            0x1b, 0x24, 0x28, 0x43, 0x33, 0x4d, 0x43, 0x56, 0x30, 0x6d, 0x3e, 0x5f,
        ];
        assert_eq!(decode(COMP).unwrap(), "넌최고야");
    }

    #[test]
    fn latin() {
        assert_eq!(
            decode(&[0x1b, 0x2d, 0x41, 0xa1, 0xb8, 0xc0]).unwrap(),
            "¡¸À"
        );
        assert_eq!(decode(&[0xe9]).unwrap(), "é");
        assert_eq!(decode(&[0x1b, 0x2d, 0x42, 0xa1, 0xa3]).unwrap(), "ĄŁ");
    }

    #[test]
    fn utf8_segment_between_ascii() {
        let mut comp = b"a".to_vec();
        comp.extend(crate::utf8_to_compound_text("中文"));
        comp.push(b'b');
        assert_eq!(decode(&comp).unwrap(), "a中文b");
    }

    #[test]
    fn garbage_never_errors() {
        for comp in [
            &[0x1b][..],
            &[0x1b, 0x24],
            &[0x1b, 0x24, 0x28, 0x5a, 0x41, 0x42],
            &[0x1b, 0x25, 0x47, 0xff, 0xfe],
            &[0x1b, 0x25, 0x2f, 0x31, 0x80, 0x85],
            &[0x1b, 0x24, 0x29, 0x41, 0xff],
        ] {
            assert!(decode(comp).is_ok());
        }
    }
}
