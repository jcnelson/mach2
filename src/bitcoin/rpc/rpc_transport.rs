// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! A simple JSON-RPC transport client using [`StacksHttpRequest`] for HTTP communication.
//!
//! This module provides a wrapper around basic JSON-RPC interactions with support
//! for configurable authentication and timeouts. It serializes requests and parses
//! responses while exposing error types for network, parsing, and service-level issues.

use std::io;
use std::time::Duration;
use std::net::TcpStream;
use std::net::ToSocketAddrs;

use serde::{Serialize, Deserialize};
use serde_json::Value;
use crate::net::http::run_http_request;
use stacks_common::types::net::PeerHost;
use url::Url;

use crate::net::Error as NetError;
use crate::bitcoin::Error;

/// The JSON-RPC protocol version used in all requests.
/// Latest specification is `2.0`
const RPC_VERSION: &str = "2.0";

/// Represents a JSON-RPC request payload sent to the server.
#[derive(Serialize)]
struct JsonRpcRequest {
    /// JSON-RPC protocol version.
    jsonrpc: String,
    /// Unique identifier for the request.
    id: String,
    /// Name of the RPC method to invoke.
    method: String,
    /// Parameters to be passed to the RPC method.
    params: serde_json::Value,
}

/// Represents a JSON-RPC response payload received from the server.
#[derive(Deserialize, Debug)]
struct JsonRpcResponse<T> {
    /// ID matching the original request.
    id: String,
    /// Result returned from the RPC method, if successful.
    result: Option<T>,
    /// Error object returned by the RPC server, if the call failed.
    error: Option<JsonRpcError>,
}

/// Represents the JSON-RPC response error received from the endpoint
#[derive(Deserialize, Debug)]
pub struct JsonRpcError {
    /// error code
    code: i32,
    /// human-readable error message
    message: String,
    /// data can be any JSON value or omitted
    data: Option<Value>,
}

/// Represents a JSON-RPC error encountered during a transport operation.
#[derive(Debug)]
pub enum RpcError {
    /// Serde decoding error
    DecodeJson(serde_json::Error),
    /// Serde encoding error
    EncodeJson(serde_json::Error),
    /// Indicates that the response doesn't contain a json payload
    InvalidJsonPayload,
    /// RPC Id mismatch between request and response
    MismatchedId(String, String),
    /// Represents an error returned by the RPC service itself.
    Service(JsonRpcError),
    /// URL missing host error
    UrlMissingHost(Url),
    /// URL missing port error
    UrlMissingPort(Url),
    /// Netowrk error
    Network(NetError),
    /// Bitcoin error
    Bitcoin(Error),
}

/// Alias for results returned from RPC operations using [`RpcTransport`].
pub type RpcResult<T> = Result<T, RpcError>;

impl From<Error> for RpcError {
    fn from(e: Error) -> Self {
        Self::Bitcoin(e)
    }
}

impl From<NetError> for RpcError {
    fn from(e: NetError) -> Self {
        Self::Network(e)
    }
}

impl From<io::Error> for RpcError {
    fn from(e: io::Error) -> Self {
        Self::Network(NetError::IO(e))
    }
}

/// Represents supported authentication mechanisms for RPC requests.
#[derive(Debug, Clone)]
pub enum RpcAuth {
    /// No authentication is applied.
    None,
    /// HTTP Basic authentication using a username and password.
    Basic { username: String, password: String },
}

/// A transport mechanism for sending JSON-RPC requests over HTTP.
///
/// This struct encapsulates the target URL, optional authentication,
/// and an internal HTTP client.
#[derive(Debug, Clone)]
pub struct RpcTransport {
    /// Host and port of the target JSON-RPC server.
    peer: PeerHost,
    /// Request path component of the URL (e.g., `/` or `/api`).
    path: String,
    /// Authentication to apply to outgoing requests.
    auth: RpcAuth,
    /// The maximum duration to wait for an HTTP request to complete.
    timeout: Duration,
}

impl RpcTransport {
    /// Creates a new `RpcTransport` with the given URL, authentication, and optional timeout.
    ///
    /// # Arguments
    ///
    /// * `url` - The JSON-RPC server endpoint.
    /// * `auth` - Authentication configuration (`None` or `Basic`).
    /// * `timeout` -  Optional timeout duration for HTTP requests. If `None`, defaults to 30 seconds.
    ///
    /// # Returns
    ///
    /// An instance of [`RpcTransport`] on success, or a [`RpcError`] otherwise.
    pub fn new(url: String, auth: RpcAuth, timeout: Option<Duration>) -> RpcResult<Self> {
        let url_obj = Url::parse(&url)
            .map_err(|e| Error::ParseError(format!("Failed to parse url: {e:?}")))?;
        let host = url_obj
            .host_str()
            .ok_or(RpcError::UrlMissingHost(url_obj.clone()))?;
        let port = url_obj
            .port_or_known_default()
            .ok_or(RpcError::UrlMissingHost(url_obj.clone()))?;

        let peer: PeerHost = format!("{host}:{port}").parse()
            .map_err(|e| Error::ParseError(format!("Failed to parse '{host}:{port}' into PeerHost: {e:?}")))?;

        let path = url_obj.path().to_string();
        let timeout = timeout.unwrap_or(Duration::from_secs(30));
        Ok(RpcTransport {
            peer,
            path,
            auth,
            timeout,
        })
    }

    /// Sends a JSON-RPC request with the given ID, method name, and parameters.
    ///
    /// # Arguments
    ///
    /// * `id` - A unique identifier for correlating responses.
    /// * `relative_path` - An optional relative path to append to the transport base path for this request.
    ///                     If `None`, the base path is used. Leading `/` in the path is handled automatically.
    /// * `method` - The name of the JSON-RPC method to invoke.
    /// * `params` - A list of parameters to pass to the method.
    ///
    /// # Returns
    ///
    /// Returns `RpcResult<T>`, which is a result containing either the successfully deserialized response of type `T`
    /// or an [`RpcError`] otherwise
    pub fn send<T: for<'de> Deserialize<'de>>(
        &self,
        id: &str,
        relative_path: Option<&str>,
        method: &str,
        params: Vec<Value>,
    ) -> RpcResult<T> {
        let payload = JsonRpcRequest {
            jsonrpc: RPC_VERSION.to_string(),
            id: id.to_string(),
            method: method.to_string(),
            params: Value::Array(params),
        };

        // TODO: try each address resolved
        let (host, port) = self.peer.to_host_port();
        let mut sockaddr_iter = (host.as_str(), port).to_socket_addrs()?;
        let sockaddr = sockaddr_iter.next().ok_or_else(|| Error::ResolutionFailed)?;
        let mut sock = TcpStream::connect_timeout(&sockaddr, self.timeout)
            .map_err(Error::NetworkError)?;

        sock.set_read_timeout(Some(self.timeout))
            .map_err(Error::NetworkError)?;
        sock.set_write_timeout(Some(self.timeout))
            .map_err(Error::NetworkError)?;
        sock.set_nodelay(true)
            .map_err(Error::NetworkError)?;

        let json_payload = serde_json::to_vec(&payload).map_err(RpcError::EncodeJson)?;
        let response_bytes = run_http_request(&mut sock, &sockaddr, "POST", &self.build_req_path(relative_path), Some("application/json"), self.auth_credentials(), &json_payload)?;
        
        let parsed_response : JsonRpcResponse<T> = serde_json::from_slice(&response_bytes)
            .map_err(RpcError::DecodeJson)?;

        if id != parsed_response.id {
            return Err(RpcError::MismatchedId(id.to_string(), parsed_response.id));
        }

        if let Some(error) = parsed_response.error {
            return Err(RpcError::Service(error));
        }

        if let Some(result) = parsed_response.result {
            Ok(result)
        } else {
            Ok(serde_json::from_value(Value::Null).map_err(RpcError::DecodeJson)?)
        }
    }

    fn auth_credentials(&self) -> Option<(&str, &str)> {
        match &self.auth {
            RpcAuth::None => None,
            RpcAuth::Basic { username, password } => Some((&username, &password))
        }
    }

    /// Build request path, joining a relative path with the transport base path
    fn build_req_path(&self, rel_path: Option<&str>) -> String {
        let rel_path = rel_path.unwrap_or("");
        let clean_rel_path = rel_path.strip_prefix("/").unwrap_or(rel_path);
        if self.path.ends_with("/") {
            format!("{}{clean_rel_path}", self.path)
        } else {
            format!("{}/{clean_rel_path}", self.path)
        }
    }
}

