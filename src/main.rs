
#![feature(thread_local)]

mod request;
mod response;
mod service;
mod sharded_prefix_set;
mod state;
mod user;
mod tl_alloc;

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

use dashmap::DashMap;
use iprange::IpRange;
use monoio::net::{TcpListener, TcpStream};
use service::ConnectionProcessor;
use smol_str::SmolStr;
use state::{State, User};

pub async fn serve_http<A>(addr: A, state: Arc<State>) -> std::io::Result<()>
where
    A: Into<SocketAddr>,
{
    let listener = TcpListener::bind(addr.into())?;

    loop {
        let (stream, _) = listener.accept().await?;
        monoio::spawn(handle_connection(stream, state.clone()));
    }
}

pub async fn handle_connection(stream: TcpStream, state: Arc<State>) {
    let mut cp = ConnectionProcessor::new(state, stream);
    if let Err(e) = cp.process().await {
        eprintln!("error on process connection: {e:?}");
    }
}

fn main() {
    eprintln!("io_uring: {}", monoio::utils::detect_uring());
    let prefixes = std::thread::spawn(|| read_countries());
    let users = read_users();
    let prefixes = prefixes.join().unwrap();

    let state = Arc::new(State::new(users, prefixes));
    let state_cln = state.clone();
    let body = async {
        let _ = serve_http(([0, 0, 0, 0], 8080), state_cln).await;
    };

    #[allow(clippy::needless_collect)]
    let threads: Vec<_> = (1..2u32)
        .map(|_| {
            let state_cln = state.clone();
            ::std::thread::spawn(|| {
                monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .expect("Failed building the Runtime")
                    .block_on(async move {
                        let _ = serve_http(([0, 0, 0, 0], 8080), state_cln).await;
                    });
            })
        })
        .collect();

    monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
        .build()
        .expect("Failed building the Runtime")
        .block_on(body);

    threads.into_iter().for_each(|t| {
        let _ = t.join();
    });
}

fn read_users() -> DashMap<SmolStr, User> {
    let start = Instant::now();

    let values = std::fs::read_to_string("/storage/data/users.jsonl").unwrap();
    let result = DashMap::with_shard_amount(16);
    for line in values.trim().split("\n") {
        let user: User = serde_json::from_str(line).unwrap();
        result.insert(user.login.clone(), user);
    }

    eprintln!("creating users: {:?}", Instant::now().duration_since(start));
    eprintln!("users-len:{}", result.len());

    result
}

fn read_countries() -> HashMap<SmolStr, IpRange<ipnet::Ipv4Net>> {
    let handl = std::thread::spawn(|| {
        std::fs::read_to_string("/storage/data/GeoLite2-City-CSV/GeoLite2-City-Blocks-IPv4.csv")
    });

    let start = Instant::now();
    let mut country_set: HashMap<SmolStr, SmolStr> = HashMap::new();
    let mut geoname_id_by_country: HashMap<SmolStr, SmolStr> = HashMap::new();

    // let locations =
    //     std::fs::read_to_string("/storage/data/GeoLite2-City-CSV/GeoLite2-City-Locations-en.csv")
    //         .unwrap();
    // let lines = locations.trim().split("\n");

    let mut rdr =
        csv::Reader::from_path("/storage/data/GeoLite2-City-CSV/GeoLite2-City-Locations-en.csv")
            .unwrap();
    for line in rdr.records() {
        let line = line.unwrap();

        let geo_name_id: SmolStr = line.get(0).unwrap().into();
        let country = line.get(5).unwrap();

        // let geo_name_id: SmolStr = line.next().unwrap().into();
        // let country = line.skip(4).next().unwrap().trim_matches('"');

        let country = if let Some(v) = country_set.get(country) {
            v.clone()
        } else {
            let country: SmolStr = country.into();
            country_set.insert(country.clone(), country.clone());
            country
        };

        geoname_id_by_country.insert(geo_name_id, country);
    }

    eprintln!("creating map: {:?}", Instant::now().duration_since(start));

    let data = handl.join().unwrap().unwrap();
    eprintln!("read_blocks: {:?}", Instant::now().duration_since(start));

    let start = Instant::now();
    let mut country_prefixes: HashMap<_, Vec<ipnet::Ipv4Net>> = HashMap::new();

    let lines = data.trim().split("\n");
    for (idx, line) in lines.skip(1).enumerate() {
        let mut line = line.split(",");
        let cidr = line.next().unwrap();
        let geoname_id = line.next().unwrap();

        // if idx == 2620546 {
        //   eprintln!("{cidr}: {geoname_id}");
        // }

        let Some(country) = geoname_id_by_country.get(geoname_id) else {
            // eprintln!("not found geoname_id: {geoname_id}");
            continue;
        };

        let cntr = country.as_str();
        let entry = country_prefixes
            .entry(country.clone())
            .or_insert_with(|| Vec::with_capacity(1000));

        entry.push(cidr.parse().unwrap());
    }

    eprintln!(
        "parse prefix_map to vec: {:?}",
        Instant::now().duration_since(start)
    );

    let mut result = HashMap::new();
    for (k, v) in country_prefixes {
        // if k.as_str() == "Bonaire, Sint Eustatius, and Saba" {
        //     eprintln!("{:?}", v);
        // }
        let mut ps = IpRange::new();
        for net in v {
            ps.add(net);
        }

        result.insert(k, ps);
    }

    eprintln!(
        "create prefix_map: {:?}",
        Instant::now().duration_since(start)
    );

    result
}
