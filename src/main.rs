mod request;
mod response;
mod service;
mod state;
mod user;

use std::{future::Future, net::SocketAddr};

use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use monoio::{io::IntoPollIo, net::TcpListener};

use crate::request::Handler;

pub async fn serve_http<S, F, E, A>(addr: A, service: S) -> std::io::Result<()>
where
    S: Copy + Fn(Request<hyper::body::Incoming>) -> F + 'static,
    F: Future<Output = Result<Response<Empty<&'static [u8]>>, E>> + 'static,
    E: std::error::Error + 'static + Send + Sync,
    A: Into<SocketAddr>,
{
    let listener = TcpListener::bind(addr.into())?;
    loop {
        let (stream, _) = listener.accept().await?;
        let stream_poll = monoio_compat::hyper::MonoioIo::new(stream.into_poll_io()?);
        monoio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(stream_poll, service_fn(service))
                .await
            {
                println!("Error serving connection: {err}");
            }
        });
    }
}

async fn health_handler(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Empty<&'static [u8]>>, std::convert::Infallible> {
    let Some(handler) = Handler::new(req.method(), req.uri().path()) else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Empty::new())
            .unwrap());
    };

    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Empty::new())
        .unwrap())
}

fn main() {
    let body = async {
        let _ = serve_http(([0, 0, 0, 0], 8080), health_handler).await;
    };

    let s = String::from_utf8(std::fs::read("/storage/data/users.jsonl").unwrap()).unwrap();
    eprintln!("users-len: {}", s.len());

    #[allow(clippy::needless_collect)]
    let threads: Vec<_> = (1..2u32)
        .map(|_| {
            ::std::thread::spawn(|| {
                monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .expect("Failed building the Runtime")
                    .block_on(async {
                        let _ = serve_http(([0, 0, 0, 0], 8080), health_handler).await;
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
