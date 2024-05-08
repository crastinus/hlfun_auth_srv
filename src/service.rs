use std::{net::Ipv4Addr, str::FromStr, sync::Arc};

use arrayvec::ArrayString;
use http::{Method, StatusCode};
use ipnet::Ipv4Net;
use jwt_simple::token::MAX_HEADER_LENGTH;
use monoio::{
    io::{AsyncReadRent, AsyncReadRentExt, AsyncWriteRentExt},
    net::TcpStream,
};
use smol_str::SmolStr;

use crate::{
    request::{AuthRequest, EditUserRequest, Handler, RegisterUserRequest},
    state::State,
};

const INIT_READ_SIZE: usize = 4096;
const MAX_HEADERS: usize = 256;
const MAX_TOKEN_LEN: usize = 256;
const MAX_IP_LEN: usize = 16;

const MAX_HEADER_SIZE: usize = 10 * 1024;
const MAX_BODY_SIZE: usize = 100 * 1024;

#[derive(Debug)]
pub enum CPError {}

pub struct ConnectionProcessor {
    state: Arc<State>,
    stream: TcpStream,
}

impl ConnectionProcessor {
    pub fn new(state: Arc<State>, stream: TcpStream) -> ConnectionProcessor {
        ConnectionProcessor { state, stream }
    }

    pub async fn process(&mut self) -> Result<(), CPError> {
        use httparse::Status as ParseStatus;

        let mut buf: Vec<u8> = Vec::with_capacity(INIT_READ_SIZE);
        let mut res;

        let mut ip: Option<ArrayString<MAX_IP_LEN>> = None;
        let mut token: Option<ArrayString<MAX_TOKEN_LEN>> = None;
        let mut content_length: Option<usize> = None;
        let mut handler = None;

        loop {
            buf.clear();
            ip = None;
            token = None;
            content_length = None;
            handler = None;

            // parsing http-header
            //
            let mut header_len = 0;
            while header_len == 0 {
                (res, buf) = self.stream.read(buf).await;
                let Ok(_sz) = res else {
                    return Ok(());
                };

                if _sz == 0 {
                    return Ok(());
                }

                if buf.len() > MAX_HEADER_SIZE {
                    self.write_code(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
                        .await
                        .unwrap();
                    return Ok(());
                }

                // lightweight parsing http body
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut req = httparse::Request::new(&mut headers);
                let res = match req.parse(buf.as_slice()) {
                    Ok(res) => res,
                    Err(err) => {
                        eprintln!("error parse buffer: {err}");
                        return Ok(());
                    }
                };

                header_len = match res {
                    ParseStatus::Partial => continue,
                    ParseStatus::Complete(compl) => compl,
                };

                let method = Method::from_str(req.method.unwrap_or_default()).unwrap_or_default();

                handler = Handler::new(&method, req.path.unwrap_or_default());

                for header in req.headers {
                    let name = StackLowerCaseStr::from_str(header.name);
                    let name = name.as_str();

                    match name {
                        "content-length" => {
                            let s = unsafe { std::str::from_utf8_unchecked(header.value) };
                            let Ok(cl) = s.parse::<usize>() else {
                                continue;
                            };
                            content_length = Some(cl);
                        }
                        "x-forwarded-for" => {
                            let ip_str = unsafe { std::str::from_utf8_unchecked(header.value) };
                            let Ok(tmp_ip) = ArrayString::from(ip_str) else {
                                eprintln!("unable to cast ip {ip_str} into ArrayString");
                                continue;
                            };
                            ip = Some(tmp_ip);
                        }
                        "x-api-key" => {
                            let api_key_str =
                                unsafe { std::str::from_utf8_unchecked(header.value) };
                            let Ok(tmp_token) = ArrayString::from(api_key_str) else {
                                eprintln!("unable to cast ip {api_key_str} into ArrayString");
                                continue;
                            };
                            token = Some(tmp_token);
                        }
                        _ => continue,
                    };
                }
            }

            let content_length = content_length.unwrap_or(0);

            while buf.len() < content_length + header_len {
                (res, buf) = self.stream.read(buf).await;
                if let Err(e) = res {
                    eprintln!("read http body: {e}");
                    return Ok(());
                }

                if buf.len() > header_len + MAX_BODY_SIZE {
                    self.write_code(StatusCode::PAYLOAD_TOO_LARGE)
                        .await
                        .unwrap();
                    return Ok(());
                }
            }

            let body = &buf[header_len..header_len + content_length];

            let handler = match handler {
                Some(handler) => handler,
                None => {
                    self.write_code(StatusCode::NOT_FOUND).await?;
                    continue;
                }
            };

            let ip = match ip {
                Some(ip) => {
                    let ip = &ip[..];

                    let Ok(ip) = Ipv4Addr::from_str(ip) else {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                        continue;
                    };

                    ip
                }
                None => {
                    self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                    continue;
                }
            };

            if self.state.is_ip_banned(ip) {
                self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                continue;
            }

            if let Handler::Auth = handler {
                let Ok(request) = serde_json::from_slice::<AuthRequest<'_>>(body) else {
                    self.write_bad_request().await.unwrap();
                    continue;
                };

                match self.state.authenticate(
                    request.login,
                    request.password.as_str(),
                    request.nonce,
                    ip,
                ) {
                    Some(token) => {
                        self.write_auth_token(StatusCode::OK, token).await.unwrap();
                    }
                    None => {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                    }
                }
                continue;
            }

            if let Handler::RegisterUser = handler {
                let Ok(request) = serde_json::from_slice::<RegisterUserRequest<'_>>(body) else {
                    self.write_bad_request().await.unwrap();
                    continue;
                };

                if self.state.is_user_exists(request.login) {
                    self.write_code(StatusCode::CONFLICT).await.unwrap();
                    continue;
                }

                self.state.create_user(
                    request.login,
                    request.password.as_str(),
                    request.name,
                    request.phone,
                    request.country,
                );

                self.write_code(StatusCode::CREATED).await.unwrap();

                continue;
            }

            let Some(tok) = token else {
                self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                continue;
            };

            let token = &tok[..];

            let Some(login) = self.state.get_user_login(token) else {
                self.write_bad_request().await.unwrap();
                continue;
            };

            if let None = self.state.is_proper_country(login.clone(), ip) {
                self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                continue;
            }

            match handler {
                Handler::Auth => {
                    todo!()
                }
                Handler::GetUser => {
                    let Some(user_str) = self.state.get_user(login, ip) else {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                        continue;
                    };

                    self.write_json(StatusCode::OK, user_str.as_str())
                        .await
                        .unwrap();
                }
                Handler::RegisterUser => {
                    todo!()
                }

                Handler::EditUser => {
                    let Ok(request) = serde_json::from_slice::<EditUserRequest<'_>>(body) else {
                        self.write_bad_request().await.unwrap();
                        continue;
                    };

                    if let None =
                        self.state
                            .edit_user(login, request.name, request.password, request.phone)
                    {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                        continue;
                    }

                    self.write_code(StatusCode::ACCEPTED).await.unwrap();
                }
                Handler::BlacklistUser { user } => {
                    if !self.state.is_prop_admin_cred(login.as_str(), ip) {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                        continue;
                    }

                    let Some(is_blacklisted_now) = self.state.ban_user(&user) else {
                        self.write_code(StatusCode::NOT_FOUND).await.unwrap();
                        continue;
                    };

                    if is_blacklisted_now {
                        self.write_code(StatusCode::CREATED).await.unwrap();
                    } else {
                        self.write_code(StatusCode::CONFLICT).await.unwrap();
                    }
                }
                Handler::UnblacklistUser { user } => {
                    if !self.state.is_prop_admin_cred(login.as_str(), ip) {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                        continue;
                    }

                    let Some(is_unblacklisted_now) = self.state.unban_user(&user) else {
                        self.write_code(StatusCode::NOT_FOUND).await.unwrap();
                        continue;
                    };

                    if is_unblacklisted_now {
                        self.write_code(StatusCode::NO_CONTENT).await.unwrap();
                    } else {
                        self.write_code(StatusCode::NOT_FOUND).await.unwrap();
                    }
                }
                Handler::BlacklistSubnet { subnet, mask } => {
                    if !self.state.is_prop_admin_cred(login.as_str(), ip) {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                        continue;
                    }

                    let Ok(ip) = Ipv4Addr::from_str(subnet.as_str()) else {
                        self.write_bad_request().await.unwrap();
                        continue;
                    };
                    let Ok(_subnet) = Ipv4Net::new(ip, mask) else {
                        self.write_bad_request().await.unwrap();
                        continue;
                    };

                    if self.state.ban_subnet(ip,mask) {
                        self.write_code(StatusCode::CREATED).await.unwrap();
                    } else {
                        self.write_code(StatusCode::CONFLICT).await.unwrap();
                    }
                }
                Handler::UnblacklistSubnet { subnet, mask } => {
                    if !self.state.is_prop_admin_cred(login.as_str(), ip) {
                        self.write_code(StatusCode::FORBIDDEN).await.unwrap();
                        continue;
                    }

                    let Ok(ip) = Ipv4Addr::from_str(subnet.as_str()) else {
                        self.write_bad_request().await.unwrap();
                        continue;
                    };
                    let Ok(_subnet) = Ipv4Net::new(ip, mask) else {
                        self.write_bad_request().await.unwrap();
                        continue;
                    };

                    if self.state.unban_subnet(ip, mask) {
                        self.write_code(StatusCode::NO_CONTENT).await.unwrap();
                    } else {
                        self.write_code(StatusCode::CONFLICT).await.unwrap();
                    }
                }
            };

            // self.write_code(StatusCode::NOT_FOUND).await.unwrap();
        }
    }

    async fn write_bad_request(&mut self) -> Result<(), CPError> {
        self.write_code(StatusCode::BAD_REQUEST).await?;
        Ok(())
    }

    async fn write_code(&mut self, code: StatusCode) -> Result<(), CPError> {
        let answer = format!(
            "HTTP/1.1 {} {}\r\nServer: Huyak-huyak\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            code.as_u16(),
            code.canonical_reason().unwrap_or("OK")
        );

        if let (Err(e), _) = self.stream.write_all(answer.into_bytes()).await {
            eprintln!(
                "error : {},  while writing status_code: {}",
                e,
                code.as_u16()
            );
        }

        Ok(())
    }

    async fn write_auth_token(&mut self, code: StatusCode, body: SmolStr) -> Result<(), CPError> {
        let answer = format!(
            "HTTP/1.1 {} {}\r\nServer: Huyak-huyak\r\nContent-type: application/json\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n\"{}\"",
            code.as_u16(),
            code.canonical_reason().unwrap_or("OK"),
            body.len() + 2,
            body
        );

        if let (Err(e), _) = self.stream.write_all(answer.into_bytes()).await {
            eprintln!("error : {},  while writing json: {}", e, body);
        }

        Ok(())
    }

    async fn write_json(&mut self, code: StatusCode, body: &str) -> Result<(), CPError> {
        let answer = format!(
            "HTTP/1.1 {} {}\r\nServer: Huyak-huyak\r\nContent-type: application/json\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n{}",
            code.as_u16(),
            code.canonical_reason().unwrap_or("OK"),
            body.len(),
            body
        );

        if let (Err(e), _) = self.stream.write_all(answer.into_bytes()).await {
            eprintln!("error : {},  while writing json: {}", e, body);
        }

        Ok(())
    }
}

struct StackLowerCaseStr {
    buffer: [u8; 32],
    len: usize,
}

impl StackLowerCaseStr {
    fn from_str(url: &str) -> StackLowerCaseStr {
        let len = if url.len() > 32 { 32 } else { url.len() };

        let mut buffer = [0u8; 32];
        for (idx, &c) in url.as_bytes().iter().enumerate() {
            buffer[idx] = c.to_ascii_lowercase();
        }

        StackLowerCaseStr { buffer, len }
    }

    fn as_str(&self) -> &'_ str {
        unsafe { std::str::from_utf8_unchecked(&self.buffer[..self.len]) }
    }
}
