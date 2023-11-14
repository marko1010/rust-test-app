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
use url::Url;
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path, collections::{HashMap, hash_map},
};
use std::{
    io::{self},
    process,
};
use rust_app::akamai_auth::{EdgeAuth, AuthOptions, Algorithm};

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

fn parse_token(input: &str, delimiter: char) -> HashMap<String, String> {
    let mut result = HashMap::new();

    for pair in input.split(delimiter) {
        let mut iter = pair.split('=');

        if let (Some(key), Some(value)) = (iter.next(), iter.next()) {
            result.insert(key.to_string(), value.to_string());
        }
    }

    result
}

fn verify_request(secret: &str, uri: &Uri) -> bool {
    const TOKEN_NAME: &str = "__token__";
    const FIELD_DELIMITER: char = '~';
    const ACL_DELIMITER: char = '!';

    let url = Url::parse(&format!("http://localhost{}",uri.to_string())).unwrap();
    let hash_query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    
    let token_string = hash_query.get(TOKEN_NAME);

    if token_string.is_none() {
        return false;
    }

    let token_params = parse_token(token_string.unwrap(), FIELD_DELIMITER);

    let mut ea = EdgeAuth{ options: AuthOptions {
        escape_early: false,
        verbose: true,
        algorithm: Algorithm::SHA256,
        start_time: token_params.get("st").and_then(|v| v.parse::<u64>().ok()),
        end_time: token_params.get("exp").and_then(|v| v.parse::<u64>().ok()),
        window_seconds: Some(10),
        ip: token_params.get("ip").and_then(|v| Some(v.to_string())),
        session_id: token_params.get("id").and_then(|v| Some(v.to_string())),
        payload: token_params.get("data").and_then(|v| Some(v.to_string())),
        salt: token_params.get("salt").and_then(|v| Some(v.to_string())),
        field_delimiter: FIELD_DELIMITER,
        acl_delimiter: ACL_DELIMITER,
        token_type: None,
        token_name: Some(TOKEN_NAME.to_string()),
        key: secret.to_string(),
    }};

    ea.verify_token(token_string.unwrap(), uri.path(), false)
}

async fn req_handler(request_headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    // write_to_cdb();
    println!("Processing request, PID: {}", process::id());

    let should_verify_token = request_headers.get("x-akam-auth").map_or(false, |uid_value| { uid_value.to_str().ok().map_or(false, |v| { v == "1" }) });

    if should_verify_token {
        let secret = request_headers.get("x-akam-secret").and_then(|v| { v.to_str().ok() });
        if secret.is_none() {
            return Err((StatusCode::BAD_REQUEST, "Missing x-akam-secret header".to_string()));
        }

        if !verify_request(secret.unwrap(), &uri) {
            return Err((StatusCode::FORBIDDEN, "Forbidden access".to_string()));
        }
    }


    let uid = request_headers.get("x-uid").and_then(|uid_value| uid_value.to_str().ok());
    if uid.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Missing x-uid header".to_string()));
    }

    let mut headers = HeaderMap::new();
    let md5 = lookup_md5(uid.unwrap(), uri.path());
    let json_response = Json(json!({ "md5": md5 }));
    headers.insert("X-aanewmd5", md5.unwrap_or_default().parse().unwrap());

    Ok((headers, json_response))
}
