use std::u8;

use http::Method;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

#[derive(Eq, PartialEq, Debug)]
pub(super) enum Handler {
    Auth,
    GetUser,
    RegisterUser,
    EditUser,
    BlacklistUser { user: SmolStr },
    UnblacklistUser { user: SmolStr },
    BlacklistSubnet { subnet: SmolStr, mask: u8 },
    UnblacklistSubnet { subnet: SmolStr, mask: u8 },
}

impl Handler {
    pub(super) fn new(method: &Method, url: &str) -> Option<Handler> {
        let mut splitted = url.split('/');
        splitted.next();

        let first_part = splitted.next()?;
        match first_part {
            "auth" => {
                if method != Method::POST {
                    return None;
                }

                if !splitted.next().is_none() {
                    return None;
                }

                return Some(Handler::Auth);
            }
            "user" => {
                if !splitted.next().is_none() {
                    return None;
                }

                match method {
                    &Method::PUT => {
                        return Some(Handler::RegisterUser);
                    }

                    &Method::GET => {
                        return Some(Handler::GetUser);
                    }

                    &Method::PATCH => {
                        return Some(Handler::EditUser);
                    }

                    _ => return None,
                }
            }
            "blacklist" => {}
            _ => return None,
        };

        let second_part = splitted.next()?;
        match second_part {
            "subnet" => {
                let ip: SmolStr = splitted.next()?.into();
                let mask: u8 = splitted.next()?.parse().ok()?;

                if !splitted.next().is_none() {
                    return None;
                }

                match method {
                    &Method::PUT => {
                        return Some(Handler::BlacklistSubnet { subnet: ip, mask });
                    }
                    &Method::DELETE => {
                        return Some(Handler::UnblacklistSubnet { subnet: ip, mask });
                    }
                    _ => return None,
                };
            }
            "user" => {
                let user: SmolStr = splitted.next()?.into();
                if !splitted.next().is_none() {
                    return None;
                }

                match method {
                    &Method::PUT => {
                        return Some(Handler::BlacklistUser { user });
                    }
                    &Method::DELETE => {
                        return Some(Handler::UnblacklistUser { user });
                    }
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct AuthRequest<'body_lf> {
    pub(super) login: &'body_lf str,
    pub(super) password: SmolStr,
    pub(super) nonce: &'body_lf str,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RegisterUserRequest<'body_lf> {
    pub(super) login: &'body_lf str,
    pub(super) password: SmolStr,
    pub(super) phone: &'body_lf str,
    pub(super) country: &'body_lf str,
    pub(super) name: &'body_lf str,
}

#[derive(Serialize, Deserialize)]
pub(super) struct EditUserRequest<'body_lf> {
    pub(super) name: Option<&'body_lf str>,
    pub(super) password: Option<SmolStr>,
    pub(super) phone: Option<&'body_lf str>,
}

#[cfg(test)]
mod test {
    use http::Method;

    use crate::request::Handler;

    #[test]
    fn test_url() {
        assert_eq!(Some(Handler::Auth), Handler::new(&Method::POST, "/auth"));
        assert_eq!(Some(Handler::GetUser), Handler::new(&Method::GET, "/user"));
        assert_eq!(
            Some(Handler::RegisterUser),
            Handler::new(&Method::PUT, "/user")
        );
        assert_eq!(
            Some(Handler::EditUser),
            Handler::new(&Method::PATCH, "/user")
        );
        assert_eq!(
            Some(Handler::BlacklistUser {
                user: "abcde".into()
            }),
            Handler::new(&Method::PUT, "/blacklist/user/abcde")
        );
        assert_eq!(
            Some(Handler::UnblacklistUser {
                user: "abcde".into()
            }),
            Handler::new(&Method::DELETE, "/blacklist/user/abcde")
        );
        assert_eq!(
            Some(Handler::BlacklistSubnet {
                subnet: "65.64.5.6".into(),
                mask: 11
            }),
            Handler::new(&Method::PUT, "/blacklist/subnet/65.64.5.6/11")
        );
        assert_eq!(
            Some(Handler::UnblacklistSubnet {
                subnet: "65.64.5.6".into(),
                mask: 11
            }),
            Handler::new(&Method::DELETE, "/blacklist/subnet/65.64.5.6/11")
        );

        assert_eq!(None, Handler::new(&Method::POST, "/auth/"));
        assert_eq!(None, Handler::new(&Method::GET, "/user/"));
        assert_eq!(None, Handler::new(&Method::PUT, "/user/"));
        assert_eq!(None, Handler::new(&Method::PATCH, "/user/"));
        assert_eq!(None, Handler::new(&Method::PUT, "/blacklist/user/abcde/"));
        assert_eq!(
            None,
            Handler::new(&Method::DELETE, "/blacklist/user/abcde/")
        );
        assert_eq!(
            None,
            Handler::new(&Method::PUT, "/blacklist/subnet/65.64.5.6/11/")
        );
        assert_eq!(
            None,
            Handler::new(&Method::DELETE, "/blacklist/subnet/65.64.5.6/11/")
        );
    }
}
