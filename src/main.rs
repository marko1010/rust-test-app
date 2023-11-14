use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, IntoMakeService},
    Json, Router, Server,
};
use docopt::Docopt;
use hyper::server::conn::AddrIncoming;
use hyperlocal::{SocketIncoming, UnixServerExt};
use rust_app::{akamai_auth::verify_request, utility::lookup_md5};
use serde::Deserialize;
use serde_json::json;
use socket2::{Domain, Socket, Type};
use std::thread::available_parallelism;
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
};

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

    let address: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap_or_else(|e| {
        panic!(
            "Error parsing the address: {}, {}",
            format!("0.0.0.0:{}", port),
            e
        )
    });
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
        .serve(app.into_make_service())
}

// #[tokio::main]
fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_socket.is_none() && args.flag_port.is_none() {
        panic!("Must specify either socket or port (or both)");
    }

    let num_of_cores = available_parallelism().unwrap().get();

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            args.flag_threads
                .and_then(|v| Some(v as usize))
                .unwrap_or(num_of_cores) as usize,
        )
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
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

            let _ = tokio::join!(
                futures::future::join_all(socket_servers),
                futures::future::join_all(port_servers)
            );
        });
}

// fn write_to_cdb() -> () {
//     let mut cdb = (cdb::CDBWriter::create("./files/downloads/incoming/cdb/g/my-uid.cdb")).unwrap();
//     let _ = cdb.add(b"a/a8/my-uid-a80a5eed12b1e1e9bd9481b9d13800b1fc437e27-mountain.jpeg", b"hash-from-downloads-incoming-old");
//     let _ = cdb.finish();
// }

async fn req_handler(request_headers: HeaderMap, uri: Uri) -> impl IntoResponse {
    // write_to_cdb();

    let should_verify_token = request_headers
        .get("x-akam-auth")
        .map_or(false, |uid_value| {
            uid_value.to_str().ok().map_or(false, |v| v == "1")
        });

    if should_verify_token {
        let secret = request_headers
            .get("x-akam-secret")
            .and_then(|v| v.to_str().ok());
        if secret.is_none() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Missing x-akam-secret header".to_string(),
            ));
        }

        let verification_result = verify_request(secret.unwrap(), &uri);
        if !verification_result.valid {
            return Err((
                StatusCode::FORBIDDEN,
                verification_result.message.unwrap().to_string(),
            ));
        }
    }

    let uid = request_headers
        .get("x-uid")
        .and_then(|uid_value| uid_value.to_str().ok());
    if uid.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Missing x-uid header".to_string()));
    }

    let mut headers = HeaderMap::new();
    let md5 = lookup_md5(uid.unwrap(), uri.path());
    let json_response = Json(json!({ "md5": md5 }));
    headers.insert("X-aanewmd5", md5.unwrap_or_default().parse().unwrap());

    Ok((headers, json_response))
}
