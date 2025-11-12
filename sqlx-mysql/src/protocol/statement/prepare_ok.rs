use bytes::{Buf, Bytes, BytesMut};
use flate2::read::ZlibDecoder;
use std::io::Read;

use crate::error::Error;
use crate::io::ProtocolDecode;
use crate::protocol::Capabilities;

#[derive(Debug)]
pub(crate) struct PrepareOk {
    pub(crate) statement_id: u32,
    pub(crate) columns: u16,
    pub(crate) params: u16,
    #[allow(unused)]
    pub(crate) warnings: u16,
}

// MySQL压缩协议头
#[derive(Debug)]
struct CompressedHeader {
    compressed_length: u32,    // 压缩后数据长度
    compressed_sequence_id: u8, // 压缩序列号
    uncompressed_length: u32,  // 压缩前数据长度
}

impl CompressedHeader {
    fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 7 {
            return Err(err_protocol!(
                "CompressedHeader expected 7 bytes but got {} bytes",
                buf.len()
            ));
        }

        let compressed_length = u32::from(buf[0]) | u32::from(buf[1]) << 8 | u32::from(buf[2]) << 16;
        let compressed_sequence_id = buf[3];
        let uncompressed_length = u32::from(buf[4]) | u32::from(buf[5]) << 8 | u32::from(buf[6]) << 16;

        Ok(Self {
            compressed_length,
            compressed_sequence_id,
            uncompressed_length,
        })
    }
}

impl ProtocolDecode<'_, Capabilities> for PrepareOk {
    fn decode_with(mut buf: Bytes, _: Capabilities) -> Result<Self, Error> {
        // 打印buf内容用于调试
        println!("=== PrepareOk Packet Debug ===");
        println!("Buffer length: {} bytes", buf.len());
        println!("Hex dump: {}", hex_dump(&buf));
        println!("As string (escaped): {}", escape_string(&buf));
        println!("==============================");
        
        // 检查是否是压缩协议
        let payload = if buf.len() == 7 {
            // 尝试解析压缩协议头
            let header = CompressedHeader::decode(&buf[..7])?;
            println!("Compressed header: {:?}", header);
            
            // 读取压缩数据
            if buf.len() < 7 + header.compressed_length as usize {
                return Err(err_protocol!(
                    "Incomplete compressed data: expected {} bytes but got {} bytes",
                    7 + header.compressed_length as usize,
                    buf.len()
                ));
            }
            
            let compressed_data = &buf[7..7 + header.compressed_length as usize];
            
            if header.uncompressed_length == 0 {
                // 数据未压缩，直接使用
                println!("Data is uncompressed, using directly");
                Bytes::copy_from_slice(compressed_data)
            } else {
                // 数据被压缩，需要解压
                println!("Decompressing data: {} -> {} bytes", 
                    header.compressed_length, header.uncompressed_length);
                
                let mut decoder = ZlibDecoder::new(compressed_data);
                let mut decompressed = Vec::with_capacity(header.uncompressed_length as usize);
                decoder.read_to_end(&mut decompressed).map_err(|e| {
                    err_protocol!("Failed to decompress data: {}", e)
                })?;
                
                println!("Decompressed to {} bytes", decompressed.len());
                Bytes::from(decompressed)
            }
        } else {
            // 不是压缩协议，使用原始数据
            buf
        };
        
        // 现在解析实际的PrepareOk包
        Self::parse_prepare_ok_payload(payload)
    }
}

impl PrepareOk {
    /// 解析实际的PrepareOk数据包负载
    fn parse_prepare_ok_payload(mut buf: Bytes) -> Result<Self, Error> {
        // PrepareOk包的最小长度：1(status) + 4(statement_id) + 2(columns) + 2(params) + 1(reserved) + 2(warnings) = 12 bytes
        const MIN_SIZE: usize = 12;
        
        if buf.len() < MIN_SIZE {
            return Err(err_protocol!(
                "PrepareOk payload expected at least {} bytes but got {} bytes",
                MIN_SIZE,
                buf.len()
            ));
        }
        
        let status = buf.get_u8();
        if status != 0x00 {
            return Err(err_protocol!(
                "expected 0x00 (COM_STMT_PREPARE_OK) but found 0x{:02x}",
                status
            ));
        }

        let statement_id = buf.get_u32_le();
        let columns = buf.get_u16_le();
        let params = buf.get_u16_le();

        buf.advance(1); // reserved: string<1>

        let warnings = buf.get_u16_le();

        Ok(Self {
            statement_id,
            columns,
            params,
            warnings,
        })
    }
}

/// 将字节缓冲区转换为十六进制字符串
fn hex_dump(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ")
}

/// 将字节缓冲区转换为转义字符串（便于查看可打印字符）
fn escape_string(buf: &[u8]) -> String {
    buf.iter()
        .map(|&b| {
            match b {
                b if b.is_ascii_graphic() || b == b' ' => char::from(b).to_string(),
                0x00 => "\\0".to_string(),
                0x09 => "\\t".to_string(),
                0x0A => "\\n".to_string(),
                0x0D => "\\r".to_string(),
                _ => format!("\\x{:02x}", b),
            }
        })
        .collect::<String>()
}

// 如果需要处理连续的压缩数据包流，可以添加这个辅助函数
pub(crate) struct PacketReader {
    buffer: BytesMut,
}

impl PacketReader {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }
    
    pub fn append_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    
    pub fn next_packet(&mut self) -> Option<Result<Bytes, Error>> {
        if self.buffer.len() < 7 {
            return None;
        }
        
        match CompressedHeader::decode(&self.buffer) {
            Ok(header) => {
                let total_needed = 7 + header.compressed_length as usize;
                if self.buffer.len() < total_needed {
                    return None;
                }
                
                // 提取整个数据包
                let packet = self.buffer.split_to(total_needed);
                Some(Ok(packet.freeze()))
            }
            Err(e) => Some(Err(e)),
        }
    }
}
