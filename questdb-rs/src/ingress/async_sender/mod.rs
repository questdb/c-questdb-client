/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
use crate::error::Result;
use crate::ingress::async_sender::http::{build_url, read_server_settings, HttpClient};
use crate::ingress::conf::{AuthParams, HttpConfig};
use crate::ingress::ndarr::ArrayElementSealed;
use crate::ingress::tls::TlsSettings;
use crate::ingress::{
    ArrayElement, Buffer, ColumnName, NdArrayView, ProtocolVersion, SenderBuilder, TableName,
    Timestamp,
};
use crate::Error;
use crossbeam_queue::ArrayQueue;
use lasso::{Spur, ThreadedRodeo};
use std::fmt::{Debug, Display};
use std::ops::Deref;
use std::sync::Arc;

mod http;

#[derive(Debug)]
pub struct TransactionFlushError {
    transaction: Transaction,
    error: Error,
}

impl Display for TransactionFlushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.error, f)
    }
}

impl std::error::Error for TransactionFlushError {}

pub struct Transaction {
    sender: Arc<AsyncSender>,
    name_key: Spur,
    buffer: Buffer,
}

impl Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("name_key", &self.name_key)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl Transaction {
    /// Get the table name associated with this transaction
    pub fn table_name(&self) -> &str {
        self.sender.names.resolve(&self.name_key)
    }

    #[inline(always)]
    pub fn reserve(&mut self, additional: usize) {
        self.buffer.reserve(additional);
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline(always)]
    pub fn row_count(&self) -> usize {
        self.buffer.row_count()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer.as_bytes()
    }

    #[inline(always)]
    pub fn set_marker(&mut self) -> Result<()> {
        self.buffer.set_marker()
    }

    #[inline(always)]
    pub fn rewind_to_marker(&mut self) -> Result<()> {
        self.buffer.rewind_to_marker()
    }

    #[inline(always)]
    pub fn clear_marker(&mut self) {
        self.buffer.clear_marker()
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.buffer.clear()
    }

    #[inline(always)]
    pub fn row(&mut self) -> Result<&mut Self> {
        let name = self.sender.names.resolve(&self.name_key);
        let name = TableName::new_unchecked(name);
        self.buffer.table(name)?;
        Ok(self)
    }

    #[inline(always)]
    pub fn symbol<'a, N, S>(&mut self, name: N, value: S) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        self.buffer.symbol(name, value)?;
        Ok(self)
    }

    #[inline(always)]
    pub fn column_bool<'a, N>(&mut self, name: N, value: bool) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.buffer.column_bool(name, value)?;
        Ok(self)
    }

    #[inline(always)]
    pub fn column_i64<'a, N>(&mut self, name: N, value: i64) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.buffer.column_i64(name, value)?;
        Ok(self)
    }

    #[inline(always)]
    pub fn column_f64<'a, N>(&mut self, name: N, value: f64) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.buffer.column_f64(name, value)?;
        Ok(self)
    }

    #[inline(always)]
    pub fn column_str<'a, N, S>(&mut self, name: N, value: S) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        self.buffer.column_str(name, value)?;
        Ok(self)
    }

    #[inline(always)]
    #[allow(private_bounds)]
    pub fn column_arr<'a, N, T, D>(&mut self, name: N, view: &T) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
        Error: From<N::Error>,
    {
        self.buffer.column_arr(name, view)?;
        Ok(self)
    }

    #[inline(always)]
    pub fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        self.buffer.column_ts(name, value)?;
        Ok(self)
    }

    pub fn at<T>(&mut self, timestamp: T) -> Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        self.buffer.at(timestamp)
    }

    /// Send the transaction batch to QuestDB.
    /// On error, the transaction is returned.
    pub async fn commit(mut self) -> std::result::Result<(), TransactionFlushError> {
        let empty_buffer = Buffer::new(self.buffer.protocol_version()); // no-alloc!
        let detached_buffer = std::mem::replace(&mut self.buffer, empty_buffer);
        let (returned_buffer, result) = self.sender.flush_buffer(detached_buffer).await;
        let _empty_buffer = std::mem::replace(&mut self.buffer, returned_buffer);
        if let Err(error) = result {
            Err(TransactionFlushError {
                transaction: self,
                error,
            })
        } else {
            Ok(())
        }
    }

    pub fn into_buffer(mut self) -> Buffer {
        let empty_buffer = Buffer::new(self.buffer.protocol_version());
        let detached_buffer = std::mem::replace(&mut self.buffer, empty_buffer);
        detached_buffer
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // Return the transaction's buffer to the sender queue
        // if it has allocated capacity and isn't too large to keep.
        let empty_buffer = Buffer::new(self.buffer.protocol_version());
        let detached_buffer = std::mem::replace(&mut self.buffer, empty_buffer);
        let cap = detached_buffer.capacity();
        if (cap > 0) && (cap <= self.sender.settings.max_buffer_capacity_keep) {
            // If the buffers queue is full, drop the buffer.
            let _ = self.sender.buffer_pool.push(detached_buffer);
        }
    }
}

pub(crate) struct AsyncSenderSettings {
    max_concurrent_connections: u16,
    max_buffer_capacity_keep: usize,
    max_name_len: usize,
    protocol_version: ProtocolVersion,
}

pub struct AsyncSender {
    descr: String,
    settings: AsyncSenderSettings,
    names: ThreadedRodeo,
    buffer_pool: ArrayQueue<Buffer>,
    client: HttpClient,
}

impl AsyncSender {
    pub async fn from_conf<T: AsRef<str>>(conf: T) -> Result<Arc<Self>> {
        SenderBuilder::from_conf(conf)?.build_async().await
    }

    pub async fn from_env() -> Result<Arc<Self>> {
        SenderBuilder::from_env()?.build_async().await
    }

    pub(crate) async fn new(
        descr: String,
        host: &str,
        port: &str,
        tls: Option<TlsSettings>,
        auth: Option<String>,
        max_name_len: usize,
        protocol_version: Option<ProtocolVersion>,
        http_config: &HttpConfig,
        max_concurrent_connections: Option<u16>,
        max_buffer_capacity_keep: Option<usize>,
    ) -> Result<Arc<Self>> {
        let settings = AsyncSenderSettings {
            max_concurrent_connections: max_concurrent_connections.unwrap_or(16),
            max_buffer_capacity_keep: max_buffer_capacity_keep.unwrap_or(8 * 1024 * 1024),
            max_name_len, // TODO: sniff and overwrite.
            protocol_version: protocol_version.unwrap_or(ProtocolVersion::V2), // TODO: sniff!
        };

        let settings_url = build_url(tls.is_some(), host, port, "settings")?;
        let client = HttpClient::new(tls, auth)?;
        let server_settings = read_server_settings(
            &client,
            &settings_url,
            max_name_len,
            *http_config.request_timeout.deref(),
        )
        .await?;

        let buffer_pool = ArrayQueue::new((settings.max_concurrent_connections as usize) * 3 / 2);
        Ok(Arc::new(Self {
            descr,
            settings,
            names: ThreadedRodeo::new(),
            buffer_pool,
            client,
        }))
    }

    pub fn new_transaction<'a, N>(self: &Arc<Self>, name: N) -> Result<Transaction>
    where
        N: TryInto<TableName<'a>>,
        Error: From<N::Error>,
    {
        let name = name.try_into()?;
        let name_key = self.names.get_or_intern(name.as_ref());
        let buffer = self.buffer_pool.pop().unwrap_or_else(|| {
            Buffer::with_max_name_len(self.settings.protocol_version, self.settings.max_name_len)
        });
        Ok(Transaction {
            sender: self.clone(),
            name_key,
            buffer,
        })
    }

    async fn flush_buffer(&self, _buffer: Buffer) -> (Buffer, Result<()>) {
        todo!()
    }
}
