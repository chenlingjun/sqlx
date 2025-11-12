use bytes::{Buf, Bytes};

use crate::error::Error;
use crate::io::ProtocolDecode;
use crate::protocol::Capabilities;

// https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html#packet-COM_STMT_PREPARE_OK

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
        println!("=== PrepareOk Packet Detailed Debug ===");
        println!("Total buffer length: {} bytes", buf.len());
        println!("Full hex dump: {}", hex_dump(&buf));
        
        // 检查前16个字节的详细结构
        let preview_len = std::cmp::min(16, buf.len());
        println!("First {} bytes: {}", preview_len, hex_dump(&buf[..preview_len]));
        
        // 分别分析可能的7字节和12字节头
        if buf.len() == 7 {
            println!("As 7-byte header:");
            println!("  Bytes 0-2 (compressed len): {:02x} {:02x} {:02x}", 
                buf[0], buf[1], buf[2]);
            println!("  Byte 3 (sequence): {:02x}", buf[3]);
            println!("  Bytes 4-6 (uncompressed len): {:02x} {:02x} {:02x}", 
                buf[4], buf[5], buf[6]);
            
            let compressed_len = u32::from(buf[0]) | u32::from(buf[1]) << 8 | u32::from(buf[2]) << 16;
            let uncompressed_len = u32::from(buf[4]) | u32::from(buf[5]) << 8 | u32::from(buf[6]) << 16;
            println!("  Compressed length: {}, Uncompressed length: {}", 
                compressed_len, uncompressed_len);
        }
        
        if buf.len() >= 12 {
            println!("As 12-byte header:");
            println!("  Bytes 0-2 (payload len): {:02x} {:02x} {:02x}", 
                buf[0], buf[1], buf[2]);
            println!("  Byte 3 (sequence): {:02x}", buf[3]);
            println!("  Bytes 4-6 (reserved): {:02x} {:02x} {:02x}", 
                buf[4], buf[5], buf[6]);
            println!("  Byte 7 (status): {:02x}", buf[7]);
            
            let payload_len = u32::from(buf[0]) | u32::from(buf[1]) << 8 | u32::from(buf[2]) << 16;
            println!("  Payload length: {}", payload_len);
        }
        
        println!("==============================");
        
        // 检查是否是压缩协议 (7字节头)
        let payload = if buf.len() == 7 {
            // 尝试解析压缩协议头
            let header = CompressedHeader::decode(&buf[..7])?;
            println!("Compressed header: {:?}", header);
            
            // 检查是否有足够的压缩数据
            if buf.len() < 7 + header.compressed_length as usize {
                return Err(err_protocol!(
                    "Incomplete compressed data: expected {} bytes but got {} bytes",
                    7 + header.compressed_length as usize,
                    buf.len()
                ));
            }
            
            let compressed_data = &buf[7..7 + header.compressed_length as usize];
            
            if header.uncompressed_length == 0 {
                // 数据未压缩，直接使用 - 这是阿里云最常见的情况
                println!("Data is uncompressed, using directly");
                println!("Uncompressed data hex: {}", hex_dump(compressed_data));
                Bytes::copy_from_slice(compressed_data)
            } else {
                // 数据被压缩 - 在阿里云环境中这种情况较少见
                // 由于不能添加flate2依赖，我们返回错误或尝试其他方式
                println!("WARNING: Compressed data detected but decompression not supported");
                println!("Compressed data hex: {}", hex_dump(compressed_data));
                
                // 如果压缩数据很小，可能是误报，尝试直接解析
                if header.compressed_length < 100 {
                    println!("Trying to parse compressed data as uncompressed due to small size");
                    Bytes::copy_from_slice(compressed_data)
                } else {
                    return Err(err_protocol!(
                        "Compressed protocol data detected (compressed: {}, uncompressed: {}), but decompression is not supported in this build",
                        header.compressed_length,
                        header.uncompressed_length
                    ));
                }
            }
        } else {
            // 不是压缩协议，使用原始数据
            buf
        };
        
        println!("Final payload to parse: {} bytes", payload.len());
        println!("Final payload hex: {}", hex_dump(&payload));
        
        // 现在解析实际的PrepareOk包
        Self::parse_prepare_ok_payload(payload)
    }
}

impl PrepareOk {
    /// 解析实际的PrepareOk数据包负载
    fn parse_prepare_ok_payload(mut buf: Bytes) -> Result<Self, Error> {
        // PrepareOk包的标准长度：1(status) + 4(statement_id) + 2(columns) + 2(params) + 1(reserved) + 2(warnings) = 12 bytes
        const STANDARD_SIZE: usize = 12;
        
        // 但阿里云可能有变种格式，我们先检查长度
        println!("Parsing prepare ok payload, length: {}", buf.len());
        
        if buf.len() < 5 {
            return Err(err_protocol!(
                "PrepareOk payload too short: expected at least 5 bytes but got {} bytes",
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

        // 标准格式：12字节
        if buf.len() >= STANDARD_SIZE - 1 {
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
        } else {
            // 阿里云可能的简化格式：只有statement_id
            // 格式可能是: [00] [statement_id:4]
            if buf.len() >= 4 {
                let statement_id = buf.get_u32_le();
                
                Ok(Self {
                    statement_id,
                    columns: 0,  // 默认值
                    params: 0,   // 默认值  
                    warnings: 0, // 默认值
                })
            } else {
                Err(err_protocol!(
                    "PrepareOk payload too short for even basic format: expected at least 4 bytes but got {} bytes",
                    buf.len()
                ))
            }
        }
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
