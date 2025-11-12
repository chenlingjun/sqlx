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
        // https://dev.mysql.com/doc/dev/mysql-server/8.0.12/page_protocol_basic_packets.html
        // https://mariadb.com/kb/en/library/0-packet/#standard-packet
    
        println!("=== 📥 [recv_packet_part] START ===");
        
        let mut header: Bytes = self.socket.read(4).await?;
        println!("🔢 [recv_packet_part] Header (4 bytes): {}", hex_dump(&header));
    
        // cannot overflow
        #[allow(clippy::cast_possible_truncation)]
        let packet_size = header.get_uint_le(3) as usize;
        let sequence_id = header.get_u8();
    
        self.sequence_id = sequence_id.wrapping_add(1);
    
        println!("📦 [recv_packet_part] Expected payload size: {}, sequence_id: {}", 
            packet_size, sequence_id);
    
        let payload: Bytes = self.socket.read(packet_size).await?;
        println!("📦 [recv_packet_part] Actual payload ({} bytes): {}", 
            payload.len(), hex_dump(&payload));
    
        // TODO: packet compression
    
        println!("=== 📥 [recv_packet_part] END (total {} bytes) ===\n", 
            4 + payload.len());
        
        Ok(payload)
    }
    
    // 在 recv_packet 方法中添加调试
    pub(crate) async fn recv_packet(&mut self) -> Result<Packet<Bytes>, Error> {
        println!("=== 🚀 [recv_packet] START ===");
        
        let payload = self.recv_packet_part().await?;
        println!("🔢 [recv_packet] Initial payload: {} bytes", payload.len());
        
        let payload = if payload.len() < 0xFF_FF_FF {
            println!("✅ [recv_packet] Single packet, no chunking needed");
            payload
        } else {
            println!("🔄 [recv_packet] Large packet, starting chunked read");
            let mut final_payload = BytesMut::with_capacity(0xFF_FF_FF * 2);
            final_payload.extend_from_slice(&payload);
    
            drop(payload); // we don't need the allocation anymore
    
            let mut last_read = 0xFF_FF_FF;
            let mut chunk_count = 1;
            while last_read == 0xFF_FF_FF {
                println!("📦 [recv_packet] Reading chunk {}", chunk_count);
                let part = self.recv_packet_part().await?;
                last_read = part.len();
                final_payload.extend_from_slice(&part);
                println!("📦 [recv_packet] Chunk {}: {} bytes", chunk_count, last_read);
                chunk_count += 1;
            }
            println!("✅ [recv_packet] Chunked read complete, total: {} bytes", 
                final_payload.len());
            final_payload.into()
        };
    
        // 检查错误包
        if let Some(&first_byte) = payload.first() {
            if first_byte == 0xff {
                println!("❌ [recv_packet] Error packet detected (0xff)");
                self.waiting.pop_front();
    
                // instead of letting this packet be looked at everywhere, we check here
                // and emit a proper Error
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
        
        Ok(Packet(payload))
    }
    
    // 在 recv 方法中添加调试
    pub(crate) async fn recv<'de, T>(&mut self) -> Result<T, Error>
    where
        T: ProtocolDecode<'de, Capabilities>,
    {
        println!("=== 🔄 [recv] START for type: {} ===", std::any::type_name::<T>());
        let packet = self.recv_packet().await?;
        println!("🔢 [recv] Packet to decode: {} bytes", packet.0.len());
        let result = packet.decode_with(self.capabilities);
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
