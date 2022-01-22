use actix_files::NamedFile;
use actix_governor::{Governor, GovernorConfigBuilder, KeyExtractor};
use actix_web::{dev::ServiceRequest, error, middleware, web, App, HttpServer, Result};
use chrono::{SubsecRound, Utc};
use clap::Parser;
use serde::Deserialize;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    net::IpAddr,
    path::PathBuf,
    sync::Mutex,
};
#[macro_use]
extern crate lazy_static;

#[derive(Parser, Debug, Clone)]
#[clap(about, version, author)]
struct Args {
    /// Bind host.
    #[clap(short, long, default_value = "0.0.0.0", env = "SRV_HOST")]
    host: String,

    /// Bind port.
    #[clap(short, long, default_value_t = 8080, env = "SRV_PORT")]
    port: u16,

    /// Output file name.
    #[clap(short, long, default_value = "./entries.csv", env = "SRV_FILENAME")]
    filename: PathBuf,

    /// Basic auth for listing entries.
    #[clap(short, long, default_value = "", env = "SRV_AUTH_LIST")]
    auth_list: String,

    /// Timeout for adding entry in seconds.
    #[clap(short, long, default_value_t = 1, env = "SRV_TIMEOUT_ADD")]
    timeout_add: u64,
}

#[derive(Deserialize, Debug, Default)]
struct LogEntry {
    #[serde(default)]
    id: String,

    #[serde(default)]
    ver: String,

    #[serde(default)]
    kernel: String,

    #[serde(default)]
    os: String,
}

#[derive(Deserialize, Debug, Default)]
struct Auth {
    #[serde(default)]
    password: String,
}

lazy_static! {
    static ref ARGS: Args = Args::parse();
    static ref FILE: Box<Mutex<File>> = {
        if let Some(parent) = ARGS.filename.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        Box::new(Mutex::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(&ARGS.filename)
                .unwrap(),
        ))
    };
}

async fn add_entry(web::Query(q): web::Query<LogEntry>) -> Result<&'static str> {
    let is_valid = |v: &str| !v.is_empty() && !v.bytes().any(|c| b"\r\n,\"".contains(&c));
    if !is_valid(&q.id) {
        return Err(error::ErrorBadRequest("Bad field: id!"));
    }
    if !is_valid(&q.os) {
        return Err(error::ErrorBadRequest("Bad field: os!"));
    }
    if !is_valid(&q.kernel) {
        return Err(error::ErrorBadRequest("Bad field: kernel!"));
    }
    if !is_valid(&q.ver) {
        return Err(error::ErrorBadRequest("Bad field: ver!"));
    }
    match FILE.lock() {
        Ok(mut file) => {
            let time = Utc::now().trunc_subsecs(0);
            match file
                .write(format!("{},{},{},{},{}\n", time, q.id, q.ver, q.kernel, q.os).as_bytes())
            {
                Ok(_) => Ok("Ok!"),
                Err(_) => Err(error::ErrorInternalServerError("Failed to write!")),
            }
        }
        Err(_) => Err(error::ErrorInternalServerError("Failed to lock!")),
    }
}

async fn list_entries(web::Query(q): web::Query<Auth>) -> Result<NamedFile> {
    if !ARGS.auth_list.is_empty() && q.password != ARGS.auth_list {
        return Err(error::ErrorUnauthorized("Bad field: password!"));
    }
    Ok(NamedFile::open(&ARGS.filename)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RealIpKeyExtractor;

impl KeyExtractor for RealIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = &'static str;

    #[cfg(feature = "log")]
    fn name(&self) -> &'static str {
        "real IP"
    }

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        // Get the reverse proxy IP that we put in app data
        let reverse_proxy_ip = req
            .app_data::<web::Data<IpAddr>>()
            .map(|ip| ip.get_ref().to_owned())
            .unwrap_or_else(|| IpAddr::from_str("0.0.0.0").unwrap());

        let peer_ip = req.peer_addr().map(|socket| socket.ip());
        let connection_info = req.connection_info();

        match peer_ip {
            // The request is coming from the reverse proxy, we can trust the `Forwarded` or `X-Forwarded-For` headers
            Some(peer) if peer == reverse_proxy_ip => connection_info
                .realip_remote_addr()
                .ok_or("Could not extract real IP address from request")
                .and_then(|str| {
                    SocketAddr::from_str(str)
                        .map(|socket| socket.ip())
                        .or_else(|_| IpAddr::from_str(str))
                        .map_err(|_| "Could not extract real IP address from request")
                }),
            // The request is not comming from the reverse proxy, we use peer IP
            _ => connection_info
                .remote_addr()
                .ok_or("Could not extract peer IP address from request")
                .and_then(|str| {
                    SocketAddr::from_str(str)
                        .map_err(|_| "Could not extract peer IP address from request")
                })
                .map(|socket| socket.ip()),
        }
    }

    #[cfg(feature = "log")]
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    lazy_static::initialize(&ARGS);
    lazy_static::initialize(&FILE);
    env_logger::init();
    let add_limit = GovernorConfigBuilder::default()
        .key_extractor(RealIpKeyExtractor::default())
        .per_second(ARGS.timeout_add)
        .burst_size(1)
        .finish()
        .unwrap();
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::new("%a \"%r\" -> %s %bb %Dms"))
            .service(
                web::resource("/list")
                    .wrap(middleware::Compress::default())
                    .route(web::get().to(list_entries)),
            )
            .service(
                web::resource("/add")
                    .wrap(Governor::new(&add_limit))
                    .route(web::get().to(add_entry)),
            )
            .service(web::resource("/").route(web::get().to(|_: web::HttpRequest| async { "Ok!" })))
    })
    .bind(format!("{}:{}", &ARGS.host, &ARGS.port))?
    .run()
    .await
}
