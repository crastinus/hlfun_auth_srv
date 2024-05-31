use std::{collections::HashMap, net::Ipv4Addr};

use dashmap::{DashMap, DashSet};
use ipnet::Ipv4Net;
use iprange::IpRange;
use jwt_simple::{
    algorithms::{HS256Key, MACLike},
    reexports::coarsetime::Duration,
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub login: SmolStr,
    #[serde(skip_serializing)]
    pub password: SmolStr,
    pub name: SmolStr,
    pub phone: SmolStr,
    pub country: SmolStr,

    #[serde(default = "default_is_admin", skip_serializing_if = "omit_empty")]
    pub is_admin: bool,

    #[serde(skip)]
    pub is_banned: bool,

    #[serde(skip)]
    pub nonce: SmolStr,
}

fn default_is_admin() -> bool {
    false
}

fn omit_empty(&b: &bool) -> bool {
    !b
}

#[derive(Serialize, Deserialize)]
struct Info {
    // DeserializeOwned workaround
    login: SmolStr,

    #[serde(skip_deserializing)]
    nonce: SmolStr,
}

pub struct State {
    pub users: DashMap<SmolStr, User>,

    // TODO: make sharding by first octet
    // pub banned: ShardedPrefixSet,
    pub first_byte_banned_subnets: DashMap<u8, Vec<ipnet::Ipv4Net>>,
    pub root_banned_subnets: DashSet<ipnet::Ipv4Net>,
    pub country_prefixes: HashMap<SmolStr, IpRange<ipnet::Ipv4Net>>,
    key: HS256Key,
}

impl State {
    pub fn new(
        users: DashMap<SmolStr, User>,
        country_prefixes: HashMap<SmolStr, IpRange<ipnet::Ipv4Net>>,
    ) -> State {
        use base64::prelude::*;

        let key_bytes = BASE64_STANDARD
            .decode(b"CGWpjarkRIXzCIIw5vXKc+uESy5ebrbOyVMZvftj19k=")
            .unwrap();

        let key = HS256Key::from_bytes(key_bytes.as_slice());

        State {
            users,
            country_prefixes,
            first_byte_banned_subnets: DashMap::with_capacity(32), //  ShardedPrefixSet::new(),
            root_banned_subnets: DashSet::with_capacity(4),
            key,
        }
    }

    pub fn authenticate(
        &self,
        login: &str,
        password: &str,
        nonce: &str,
        ip: Ipv4Addr,
    ) -> Option<String> {
        // self.check_user_baned(login)?;
        let (login, nonce, country) = {
            let mut user = self.users.get_mut(login)?;

            if user.password != password {
                return None;
            }

            if user.is_banned {
                return None;
            }

            user.nonce = nonce.into();

            (user.login.clone(), user.nonce.clone(), user.country.clone())
        };

        self.is_country_ip(country, ip)?;

        let info = Info {
            login: login.clone(),
            nonce,
        };

        let mut cus = jwt_simple::claims::Claims::with_custom_claims(info, Duration::from_days(1));
        cus.issued_at = None;
        cus.invalid_before = None;
        cus.expires_at = None;

        let token = self.key.authenticate(cus).ok()?;

        Some(token)
    }

    fn is_country_ip(&self, country: SmolStr, ip: Ipv4Addr) -> Option<()> {
        let country = self.country_prefixes.get(&country)?;
        let subnet = Ipv4Net::new(ip, 32).unwrap();
        if !country.contains(&subnet) {
            return None;
        }

        Some(())
    }

    pub fn create_user(&self, login: &str, password: &str, name: &str, phone: &str, country: &str) {
        let user = User {
            login: login.into(),
            password: password.into(),
            name: name.into(),
            phone: phone.into(),
            country: country.into(),
            is_admin: false,
            is_banned: false,
            nonce: "".into(),
        };

        self.users.insert(user.login.clone(), user);
    }

    pub fn is_user_exists(&self, login: &str) -> bool {
        self.users.contains_key(login)
    }

    pub fn is_prop_admin_cred(&self, login: &str, ip: Ipv4Addr) -> bool {
        let country = match self.users.get(login) {
            Some(usr) => {
                if !usr.is_admin {
                    return false;
                }
                usr.value().country.clone()
            }
            None => return false,
        };

        self.is_country_ip(country, ip).is_some()
    }

    pub fn get_user(&self, login: SmolStr, ip: Ipv4Addr) -> Option<String> {
        // self.check_user_baned(login.as_str())?;
        let user = {
            let Some(rec) = self.users.get(&login) else {
                return None;
            };

            if rec.value().is_banned {
                return None;
            }

            rec.value().clone()
        };

        self.is_country_ip(user.country.clone(), ip)?;

        Some(serde_json::to_string(&user).unwrap())
    }

    pub fn is_proper_country(&self, login: SmolStr, ip: Ipv4Addr) -> Option<()> {
        let country = self.users.get(&login)?.value().country.clone();
        self.is_country_ip(country, ip);

        Some(())
    }

    pub fn edit_user(
        &self,
        login: SmolStr,
        name: Option<&str>,
        password: Option<SmolStr>,
        phone: Option<&str>,
        is_admin: Option<bool>,
        country: Option<SmolStr>,
    ) -> Option<()> {
        let mut usr = self.users.get_mut(&login).unwrap();

        if usr.is_banned {
            return None;
        }

        if let Some(is_admin) = is_admin {
            if usr.is_admin {
                usr.is_admin = is_admin;
            }
        }

        if let Some(country) = country {
            usr.country = country;
        }

        if let Some(pass) = password {
            usr.password = pass;
        }

        if let Some(name) = name {
            usr.name = name.into();
        }

        if let Some(phone) = phone {
            usr.phone = phone.into();
        }

        Some(())
    }

    pub fn get_user_login(&self, jwt: &str) -> Option<SmolStr> {
        let claims = self.key.verify_token::<Info>(jwt, None).ok()?;
        if !self.users.contains_key(&claims.custom.login) {
            return None;
        }

        Some(claims.custom.login)
    }

    pub fn ban_user(&self, login: &str) -> Option<bool> {
        let mut rec = self.users.get_mut(login)?;
        if rec.is_banned {
            return Some(false);
        }
        rec.is_banned = true;
        Some(true)
    }

    pub fn unban_user(&self, login: &str) -> Option<bool> {
        let mut rec = self.users.get_mut(login)?;
        if !rec.is_banned {
            return Some(false);
        }
        rec.is_banned = false;
        Some(true)
    }

    pub fn is_ip_banned(&self, ip: Ipv4Addr) -> bool {
        if let Some(subnets) = self.first_byte_banned_subnets.get(&ip.octets()[0]) {
            for subnet in subnets.value() {
                if subnet.contains(&ip) {
                    return true;
                }
            }
        }

        // for subnet in self.root_banned_subnets.iter() {
        //     if subnet.contains(&ip) {
        //         return true;
        //     }
        // }

        false
    }

    pub fn ban_subnet(&self, network: Ipv4Addr, mask: u8) -> bool {
        let fb = network.octets()[0];
        let subnet = Ipv4Net::new(network, mask).unwrap();

        // if mask < 8 {
        //     if self.root_banned_subnets.contains(&subnet) {
        //         return false;
        //     }

        //     self.root_banned_subnets.insert(subnet);
        //     true
        // } else {
            let mut fb = self.first_byte_banned_subnets.entry(fb).or_default();
            for &stored_subnet in fb.value().iter() {
                if stored_subnet == subnet {
                    return false;
                }
            }
            fb.push(subnet);
            true
        // }

        // if self.first_byte_banned_subnets.contains(&subnet) {
        //     return false;
        // }
        // self.first_byte_banned_subnets.insert(subnet);

        // self.banned.contains(subnet)
    }

    pub fn unban_subnet(&self, network: Ipv4Addr, mask: u8) -> bool {
        let fb = network.octets()[0];
        let subnet = Ipv4Net::new(network, mask).unwrap();

        if mask < 8 {
            if !self.root_banned_subnets.contains(&subnet) {
                return false;
            }

            self.root_banned_subnets.remove(&subnet);
            true
        } else {
            let retain: bool = {
                let Some(mut subnets) = self.first_byte_banned_subnets.get_mut(&fb) else {
                    return false;
                };

                match subnets.iter().position(|&snet| snet == subnet) {
                    Some(idx) => {
                        subnets.remove(idx);
                        true
                    }

                    None => return false,
                }
            };

            if retain {
                self.first_byte_banned_subnets.retain(|_k, v| !v.is_empty());
            }

            true
        }
    }
}
