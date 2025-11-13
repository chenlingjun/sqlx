use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};

use bytes::{Buf, Bytes, BytesMut};

use crate::collation::{CharSet, Collation};
use crate::error::Error;
use crate::io::MySqlBufExt;
use crate::io::{ProtocolDecode, ProtocolEncode};
use crate::net::{BufferedSocket, Socket};
use crate::protocol::response::{EofPacket, ErrPacket, OkPacket, Status};
use crate::protocol::{Capabilities, Packet};
use crate::{MySqlConnectOptions, MySqlDatabaseError};

pub struct MySqlStream<S = Box<dyn Socket>> {
    // Wrapping the socket in `Box` allows us to unsize in-place.
    pub(crate) socket: BufferedSocket<S>,
    pub(crate) server_version: (u16, u16, u16),
    pub(super) capabilities: Capabilities,
    pub(crate) sequence_id: u8,
    pub(crate) waiting: VecDeque<Waiting>,
    pub(crate) charset: CharSet,
    pub(crate) collation: Collation,
    pub(crate) is_tls: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Waiting {
    // waiting for a result set
    Result,

    // waiting for a row within a result set
    Row,
}

impl<S: Socket> MySqlStream<S> {
    pub(crate) fn with_socket(
        charset: CharSet,
        collation: Collation,
        options: &MySqlConnectOptions,
        socket: S,
    ) -> Self {
        let mut capabilities = Capabilities::PROTOCOL_41
            | Capabilities::IGNORE_SPACE
            | Capabilities::DEPRECATE_EOF
            | Capabilities::FOUND_ROWS
            | Capabilities::TRANSACTIONS
            | Capabilities::SECURE_CONNECTION
            | Capabilities::PLUGIN_AUTH_LENENC_DATA
            | Capabilities::MULTI_STATEMENTS
            | Capabilities::MULTI_RESULTS
            | Capabilities::PLUGIN_AUTH
            | Capabilities::PS_MULTI_RESULTS
            | Capabilities::SSL;

        if options.database.is_some() {
            capabilities |= Capabilities::CONNECT_WITH_DB;
        }

        Self {
            waiting: VecDeque::new(),
            capabilities,
            server_version: (0, 0, 0),
            sequence_id: 0,
            collation,
            charset,
            socket: BufferedSocket::new(socket),
            is_tls: false,
        }
    }

    pub(crate) async fn wait_until_ready(&mut self) -> Result<(), Error> {
        if !self.socket.write_buffer().is_empty() {
            self.socket.flush().await?;
        }

        while !self.waiting.is_empty() {
            while self.waiting.front() == Some(&Waiting::Row) {
                let packet = self.recv_packet().await?;

                if !packet.is_empty() && packet[0] == 0xfe && packet.len() < 9 {
                    let eof = packet.eof(self.capabilities)?;

                    if eof.status.contains(Status::SERVER_MORE_RESULTS_EXISTS) {
                        *self.waiting.front_mut().unwrap() = Waiting::Result;
                    } else {
                        self.waiting.pop_front();
                    };
                }
            }

            while self.waiting.front() == Some(&Waiting::Result) {
                let packet = self.recv_packet().await?;

                if !packet.is_empty() && (packet[0] == 0x00 || packet[0] == 0xff) {
                    let ok = packet.ok()?;

                    if !ok.status.contains(Status::SERVER_MORE_RESULTS_EXISTS) {
                        self.waiting.pop_front();
                    }
                } else {
                    *self.waiting.front_mut().unwrap() = Waiting::Row;
                    self.skip_result_metadata(packet).await?;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn send_packet<'en, T>(&mut self, payload: T) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.sequence_id = 0;
        self.write_packet(payload)?;
        self.flush().await?;
        Ok(())
    }

    pub(crate) fn write_packet<'en, T>(&mut self, payload: T) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.socket
            .write_with(Packet(payload), (self.capabilities, &mut self.sequence_id))
    }

    // 在 recv_packet_part 方法中添加调试
    async fn recv_packet_part(&mut self) -> Result<Bytes, Error> {
        println!("=== 📥 [recv_packet_part] START ===");
        
        // 读取4字节头
        let mut header: Bytes = self.socket.read(4).await?;
        println!("🔢 [recv_packet_part] Header (4 bytes): {}", hex_dump(&header));
    
        let packet_size = header.get_uint_le(3) as usize;
        let sequence_id = header.get_u8();
    
        self.sequence_id = sequence_id.wrapping_add(1);
    
        println!("📦 [recv_packet_part] Expected payload size: {}, sequence_id: {}", 
            packet_size, sequence_id);
    
        // 关键调试：记录读取前的状态
        println!("🔍 [recv_packet_part] About to read {} bytes of payload", packet_size);
        
        let payload: Bytes = self.socket.read(packet_size).await?;
        println!("📦 [recv_packet_part] Actual payload ({} bytes): {}", 
            payload.len(), hex_dump(&payload));
    
        // 详细检查大小不匹配的情况
        if payload.len() != packet_size {
            println!("❌ [recv_packet_part] CRITICAL: PAYLOAD SIZE MISMATCH!");
            println!("   Expected: {} bytes, but got: {} bytes", packet_size, payload.len());
            println!("   Header was: {}", hex_dump(&[header[0], header[1], header[2]]));
            println!("   This indicates a network or socket reading issue!");
            
            // 如果是7字节但期望12字节，特别记录
            if packet_size == 12 && payload.len() == 7 {
                println!("🚨 SPECIFIC ALIYUN ISSUE: Expected 12-byte PrepareOk but got only 7 bytes!");
                println!("   This explains why PrepareOk parsing fails!");
            }
        }
    
        println!("=== 📥 [recv_packet_part] END (total {} bytes) ===\n", 
            4 + payload.len());
        
        Ok(payload)
    }
    
    // 在 recv_packet 方法中添加调试
    pub(crate) async fn recv_packet(&mut self) -> Result<Packet<Bytes>, Error> {
        println!("=== 🚀 [recv_packet] START ===");
        
        let payload = self.recv_packet_part().await?;
        println!("🔢 [recv_packet] Initial payload: {} bytes", payload.len());
        
        // 检查错误包 - 使用 payload
        if let Some(&first_byte) = payload.first() {
            if first_byte == 0xff {
                println!("❌ [recv_packet] Error packet detected (0xff)");
                self.waiting.pop_front();
                return Err(
                    MySqlDatabaseError(ErrPacket::decode_with(payload, self.capabilities)?).into(),
                );
            }
        } else {
            println!("⚠️ [recv_packet] Empty packet received");
            return Err(err_protocol!("Packet empty"));
        }
        
        println!("✅ [recv_packet] Success, returning {} bytes", payload.len());
        println!("=== 🚀 [recv_packet] END ===\n");
        
        Ok(Packet(payload))  // 使用 payload
    }
    
    // 在 recv 方法中添加调试
    pub(crate) async fn recv<'de, T>(&mut self) -> Result<T, Error>
    where
        T: ProtocolDecode<'de, Capabilities>,
    {
        println!("=== 🔄 [recv] START for type: {} ===", std::any::type_name::<T>());
        
        let packet = self.recv_packet().await?;
        println!("🔢 [recv] Packet to decode: {} bytes", packet.0.len());
        
        // 🔥 关键修复：如果是 PrepareOk，特别处理阿里云的7字节包
        let result = if std::any::type_name::<T>().contains("PrepareOk") {
            self.handle_prepare_ok_with_aliyun_workaround(packet).await
        } else {
            packet.decode_with(self.capabilities)
        };
        
        println!("=== 🔄 [recv] END ===\n");
        result
    }

    pub(crate) async fn recv_ok(&mut self) -> Result<OkPacket, Error> {
        self.recv_packet().await?.ok()
    }

    pub(crate) async fn maybe_recv_eof(&mut self) -> Result<Option<EofPacket>, Error> {
        if self.capabilities.contains(Capabilities::DEPRECATE_EOF) {
            Ok(None)
        } else {
            self.recv().await.map(Some)
        }
    }

    async fn skip_result_metadata(&mut self, mut packet: Packet<Bytes>) -> Result<(), Error> {
        let num_columns: u64 = packet.get_uint_lenenc(); // column count

        for _ in 0..num_columns {
            let _ = self.recv_packet().await?;
        }

        self.maybe_recv_eof().await?;

        Ok(())
    }

    pub fn boxed_socket(self) -> MySqlStream {
        MySqlStream {
            socket: self.socket.boxed(),
            server_version: self.server_version,
            capabilities: self.capabilities,
            sequence_id: self.sequence_id,
            waiting: self.waiting,
            charset: self.charset,
            collation: self.collation,
            is_tls: self.is_tls,
        }
    }

        
    async fn handle_prepare_ok_with_aliyun_workaround<'de, T>(&mut self, first_packet: Packet<Bytes>) -> Result<T, Error> 
    where
        T: ProtocolDecode<'de, Capabilities>,
    {
        println!("🔧 [handle_prepare_ok_with_aliyun_workaround] Aliyun RDS workaround");
        
        let mut packet = first_packet;
        let mut skipped_packets = 0;
        
        loop {
            // 跳过所有7字节的包（阿里云的特殊包）
            if packet.0.len() == 7 && packet.0[0] == 0x00 {
                println!("   ⏩ Skipping Aliyun 7-byte packet (#{})", skipped_packets + 1);
                packet = self.recv_packet().await?;
                skipped_packets += 1;
                continue;
            }
            
            // 尝试解码
            match packet.decode_with(self.capabilities) {
                Ok(prepare_ok) => {
                    // if skipped_packets > 0 {
                    //     println!("   ✅ Success after skipping {} Aliyun packets", skipped_packets);
                    // }
                    println!("   ✅ Success after skipping {} Aliyun packets", skipped_packets);
                    return Ok(prepare_ok);
                },
                Err(e) => {
                    println!("   ❌ Decode failed: {}", e);
                    
                    // 安全限制：最多处理10个包
                    if skipped_packets >= 10 {
                        return Err(err_protocol!("Too many invalid packets ({})", skipped_packets));
                    }
                    
                    // 继续读取下一个包
                    packet = self.recv_packet().await?;
                    skipped_packets += 1;
                }
            }
        }
    }
}

impl<S> Deref for MySqlStream<S> {
    type Target = BufferedSocket<S>;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<S> DerefMut for MySqlStream<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

// 添加 hex_dump 工具函数（如果还没有的话）
fn hex_dump(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ")
}
