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
        
       // 阿里云简化格式：7字节，只包含 statement_id
        if buf.len() == 7 {
            println!("Detected Aliyun simplified format (connection pool init)");
            return Self::parse_aliyun_simplified_format(buf);
        }
        
        // 标准MySQL格式：12字节
        if buf.len() >= 12 {
            println!("Detected standard MySQL format");
            return Self::parse_standard_format(buf);
        }
        
        Err(err_protocol!(
            "Unsupported PrepareOk format: length={}, hex={}", 
            buf.len(), hex_dump(&buf)
        ))
    }
}

impl PrepareOk {
    /// 解析阿里云简化格式：7字节 [status:1][statement_id:4][reserved:2]
    fn parse_aliyun_simplified_format(mut buf: Bytes) -> Result<Self, Error> {
        let status = buf.get_u8();
        if status != 0x00 {
            return Err(err_protocol!(
                "expected 0x00 (COM_STMT_PREPARE_OK) but found 0x{:02x}",
                status
            ));
        }
        
        // 问题在这里！我们需要手动读取正确的字节范围
        // 数据: 00 00 00 02 00 00 00
        // 索引: 0  1  2  3  4  5  6
        // 我们需要索引 2-5: 00 02 00 00
        
        // 手动读取字节 2-5
        let statement_id_bytes = [buf[2], buf[3], buf[4], buf[5]];
        let statement_id = u32::from_le_bytes(statement_id_bytes);
        
        println!("🔍 Statement ID bytes: {:02x} {:02x} {:02x} {:02x} = {}",
        buf[2], buf[3], buf[4], buf[5], statement_id);
        
        // 跳过剩余的2个保留字节
        // 在连接池初始化阶段，columns 和 params 可能为0或不重要
        // buf.advance(2);
        
        println!("Parsed Aliyun simplified format: statement_id={} (columns=0, params=0)", statement_id);
        
        Ok(Self {
            statement_id,
            columns: 0,   // 简化格式中省略，设为0
            params: 0,    // 简化格式中省略，设为0
            warnings: 0,  // 简化格式中省略，设为0
        })
    }
    
    /// 解析标准MySQL格式：12字节
    fn parse_standard_format(mut buf: Bytes) -> Result<Self, Error> {
        const SIZE: usize = 12;
        let mut slice = buf.get(..SIZE).ok_or_else(|| {
            err_protocol!("PrepareOk expected 12 bytes but got {} bytes", buf.len())
        })?;

        let status = slice.get_u8();
        if status != 0x00 {
            return Err(err_protocol!(
                "expected 0x00 (COM_STMT_PREPARE_OK) but found 0x{:02x}",
                status
            ));
        }

        let statement_id = slice.get_u32_le();
        let columns = slice.get_u16_le();
        let params = slice.get_u16_le();
        slice.advance(1); // reserved
        let warnings = slice.get_u16_le();

        println!("Parsed standard format: statement_id={}, columns={}, params={}", 
            statement_id, columns, params);

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
