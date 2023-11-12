use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, IntoMakeService},
    Json, Router, Server,
};
use chrono::Utc;
use docopt::Docopt;
use hyperlocal::{SocketIncoming, UnixServerExt};
use hyper::server::conn::AddrIncoming;
use md5;
use serde::Deserialize;
use serde_json::json;
use sha1::{Digest, Sha1};
use socket2::{Domain, Socket, Type};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
};
use std::{
    io::{self},
    process,
};

fn get_sha1(input: &str) -> String {
    let mut hasher = Sha1::new();

    hasher.update(input);

    let result = hasher.finalize();
    let hash_str = result
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    hash_str
}

const USAGE: &'static str = "
Usage: rust-app [-t <threads>] [-s <socket>]... [-p <port>]...
       rust-app (-h | --help)

Options:
    -h, --help             Show this message.
    -t, --threads=<N>      Specify number of threads
    -s, --socket=<socket>       Socket to bind to
    -p, --port=<port>     Port number to listen to
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_threads: Option<i32>,
    flag_socket: Option<Vec<String>>,
    flag_port: Option<Vec<i32>>,
}

fn create_server_on_socket(socket: &str) -> Server<SocketIncoming, IntoMakeService<Router>> {
    let app = Router::new()
        .route("/*key", get(req_handler))
        .route("/", get(req_handler));

    let path = Path::new(socket);

    if path.exists() {
        let _ = fs::remove_file(path);
    }

    axum::Server::bind_unix(path)
        .expect("Can't bind to the socket!")
        .serve(app.into_make_service())
    //  .await
}

fn create_server_on_port(port: i32) -> Server<AddrIncoming, IntoMakeService<Router>> {
    let app = Router::new()
        .route("/*key", get(req_handler))
        .route("/", get(req_handler));

    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();

    let address: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap_or_else(|e| { panic!("Error parsing the address: {}, {}", format!("0.0.0.0:{}", port), e)});
    let _ = socket.set_only_v6(false);
    _ = socket.set_reuse_port(true);
    _ = socket
        .bind(&address.into())
        .is_err_and(|e| panic!("Error binding the socket: {}", e));
    _ = socket
        .listen(128)
        .is_err_and(|e| panic!("Error listening to socket: {}", e));

    let listener: TcpListener = socket.into();

    axum::Server::from_tcp(listener)
        .unwrap()
        .serve(app.clone().into_make_service())
}

#[tokio::main]
async fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_socket.is_none() && args.flag_port.is_none() {
        panic!("Must specify either socket or port (or both)");
    }

    let mut socket_servers: Vec<Server<SocketIncoming, IntoMakeService<Router>>> = vec![];
    let mut port_servers: Vec<Server<AddrIncoming, IntoMakeService<Router>>> = vec![];

    if args.flag_socket.is_some() {
        for socket in args.flag_socket.unwrap() {
            socket_servers.push(create_server_on_socket(&socket));
        }
    }

    if args.flag_port.is_some() {
        for port in args.flag_port.unwrap() {
            port_servers.push(create_server_on_port(port));
        }
    }

    let _ = tokio::join!(futures::future::join_all(socket_servers), futures::future::join_all(port_servers));
}

fn get_hash(uid: &str, path: &str) -> (String, String) {
    let filepath = Path::new(path);
    let filename = filepath.file_name().unwrap().to_string_lossy().to_string();
    let hash = get_sha1(format!("{uid}flyIT{path}").as_str());
    let h1 = &hash[0..1];
    let h2 = &hash[1..2];
    (
        format!("/{h1}/{h2}/{uid}-{hash}"),
        format!("/{h1}/{h2}/{uid}-{hash}-{filename}"),
    )
}

fn lookup_cdb(cdb: &Result<cdb::CDB, io::Error>, key: &str) -> Option<String> {
    cdb.as_ref().ok().and_then(|cdb| {
        cdb.get(key.as_bytes()).and_then(|val| {
            val.ok()
                .and_then(|vector_u8| String::from_utf8(vector_u8).ok())
        })
    })
}

fn lookup_md5(uid: &str, path: &str) -> Option<String> {
    let hash: (String, String) = get_hash(uid, path);
    let md5_hash = format!("{:x}", md5::compute(format!("{uid}{}", hash.0)));
    if let Ok(md5) = fs::read_to_string(format!("files/ram/rtpurge/{}", md5_hash)) {
        return Some(md5.replace("\r\n", "").replace("\n", ""));
    }

    let today = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
    let yesterday = today - chrono::Duration::days(1);

    lookup_cdb(
        &cdb::CDB::open(format!("files/ram/journal-cdb/{}.cdb", today.timestamp())),
        &hash.0,
    )
    .or(lookup_cdb(
        &cdb::CDB::open(format!(
            "files/ram/journal-cdb/{}.cdb",
            yesterday.timestamp()
        )),
        &hash.0,
    ))
    .or_else(|| {
        let lastchar = &hash.1[hash.1.len() - 1..];
        let cdb = cdb::CDB::open(format!("files/downloads/incoming/cdb/{lastchar}/{uid}.cdb"));
        lookup_cdb(&cdb, &hash.0).or(lookup_cdb(&cdb, &hash.1[1..]))
    })
    .or_else(|| {
        println!("looking up basetime, uid: {}", uid);
        if let Ok(md5) = fs::read_to_string(format!("files/ram/DB/{}.basetime", uid)) {
            println!("found: {}", md5);
            return Some(md5.replace("\r\n", "").replace("\n", ""));
        } else {
            println!("not found");
            return None;
        }
    })
}

// fn write_to_cdb() -> () {
//     let mut cdb = (cdb::CDBWriter::create("./files/downloads/incoming/cdb/g/my-uid.cdb")).unwrap();
//     let _ = cdb.add(b"a/a8/my-uid-a80a5eed12b1e1e9bd9481b9d13800b1fc437e27-mountain.jpeg", b"hash-from-downloads-incoming-old");
//     let _ = cdb.finish();
// }

async fn req_handler(request_headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    // write_to_cdb();
    println!("Processing request, PID: {}", process::id());
    let uid: &str;
    if let Some(uid_value) = request_headers.get("x-uid") {
        if let Some(uid_value_to_str) = uid_value.to_str().ok() {
            uid = uid_value_to_str
        } else {
            return Err((StatusCode::BAD_REQUEST, "Missing x-uid header".to_string()));
        }
    } else {
        return Err((StatusCode::BAD_REQUEST, "Missing x-uid header".to_string()));
    }

    println!("uri path: {}", uri.path());
    let mut headers = HeaderMap::new();
    let md5 = lookup_md5(uid, uri.path());
    let json_response = Json(json!({ "md5": md5 }));
    headers.insert("X-aanewmd5", md5.unwrap_or_default().parse().unwrap());

    Ok((headers, json_response))
}
