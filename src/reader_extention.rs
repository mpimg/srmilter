use std::io::BufRead;
use std::io::Read;
use std::io::Result;

pub trait ReadExt {
    fn read_char(&mut self) -> Result<char>;
    fn read_u32_be(&mut self) -> Result<u32>;
    fn read_bytes(&mut self, len: usize, data: &mut Vec<u8>) -> Result<()>;
}

impl<T: Read> ReadExt for T {
    fn read_char(&mut self) -> Result<char> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0] as char)
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    fn read_bytes(&mut self, len: usize, data: &mut Vec<u8>) -> Result<()> {
        data.resize(len, 0u8);
        self.read_exact(data)?;
        Ok(())
    }
}

pub trait BufReadExt {
    fn read_zbytes<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<&'a [u8]>;
    fn read_zstring(&mut self, buffer: &mut Vec<u8>) -> Result<String>;
    fn read_zstring_anglestripped(&mut self, buffer: &mut Vec<u8>) -> Result<String>;
}

impl<T: BufRead> BufReadExt for T {
    fn read_zbytes<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<&'a [u8]> {
        buffer.clear();
        self.read_until(b'\0', buffer)?;
        if let Some(pos) = buffer.iter().rposition(|&x| x != 0) {
            Ok(&buffer[0..=pos])
        } else {
            Ok(&buffer[..])
        }
    }
    fn read_zstring(&mut self, buffer: &mut Vec<u8>) -> Result<String> {
        Ok(String::from_utf8_lossy(self.read_zbytes(buffer)?).to_string())
    }
    fn read_zstring_anglestripped(&mut self, buffer: &mut Vec<u8>) -> Result<String> {
        let s = anglestrip(self.read_zbytes(buffer)?);
        Ok(String::from_utf8_lossy(s).to_string())
    }
}

fn anglestrip(s: &[u8]) -> &[u8] {
    if s.len() > 1 && s[0] == b'<' && s[s.len() - 1] == b'>' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[test]
fn test_read_char() {
    let input = [b'a', b'b'];
    let mut reader = &input[..];
    assert_eq!(reader.read_char().unwrap(), 'a');
    assert_eq!(reader.read_char().unwrap(), 'b');
    reader.read_char().unwrap_err();
}

#[test]
fn test_read_u32() {
    let input = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let mut reader = &input[..];
    let v = reader.read_u32_be().unwrap();
    assert_eq!(v, 0x11223344);
    reader.read_u32_be().unwrap_err();
}

#[test]
fn test_read_bytes() {
    let input = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let mut reader = &input[..];
    let mut out: Vec<u8> = Vec::new();
    reader.read_bytes(3, &mut out).unwrap();
    assert_eq!(out, [0x11, 0x22, 0x33]);
    reader.read_bytes(0, &mut out).unwrap();
    assert_eq!(out, []);
    reader.read_bytes(4, &mut out).unwrap_err();
}

#[test]
fn test_read_zbytes() {
    use std::io::Cursor;
    let input = b"Test1\0Test2\0Test3";
    let mut reader = Cursor::new(&input);
    let mut buffer: Vec<u8> = Vec::new();
    assert_eq!(reader.read_zbytes(&mut buffer).unwrap(), b"Test1");
    assert_eq!(reader.read_zbytes(&mut buffer).unwrap(), b"Test2");
    assert_eq!(reader.read_zbytes(&mut buffer).unwrap(), b"Test3");
    assert_eq!(reader.read_zbytes(&mut buffer).unwrap(), b"");
}

#[test]
fn test_read_zstring() {
    use std::io::Cursor;
    let input = b"Test1\0Test2\0Test3";
    let mut reader = Cursor::new(&input);
    let mut buffer: Vec<u8> = Vec::new();
    assert_eq!(reader.read_zstring(&mut buffer).unwrap(), "Test1");
    assert_eq!(reader.read_zstring(&mut buffer).unwrap(), "Test2");
    assert_eq!(reader.read_zstring(&mut buffer).unwrap(), "Test3");
    assert_eq!(reader.read_zstring(&mut buffer).unwrap(), "");
}

#[test]
fn test_read_zstring_anglestripped() {
    use std::io::Cursor;
    let input = b"<Test1>\0<Test2\0Test3>";
    let mut reader = Cursor::new(&input);
    let mut buffer: Vec<u8> = Vec::new();
    assert_eq!(
        reader.read_zstring_anglestripped(&mut buffer).unwrap(),
        "Test1"
    );
    assert_eq!(
        reader.read_zstring_anglestripped(&mut buffer).unwrap(),
        "<Test2"
    );
    assert_eq!(
        reader.read_zstring_anglestripped(&mut buffer).unwrap(),
        "Test3>"
    );
}
