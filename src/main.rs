use axum::{
    extract::Query,
    http::{Uri, HeaderMap},
    routing::get,
    Json, Router, response::IntoResponse,
};
use chrono::{Utc};
use md5;
use serde::Deserialize;
use serde_json::json;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::{self};
use std::path::Path;

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

#[derive(Deserialize, Debug)]
struct QueryParams {
    uid: String
}

#[tokio::main]
async fn main() {
    // build our application with a single route
    let app = Router::new()
        .route("/*key", get(req_handler))
        .route("/", get(req_handler));

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
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

fn lookup_cdb (cdb: &Result<cdb::CDB, io::Error>, key: &str) -> Option<String> {
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
        return Some(md5);
    }

    let today = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
    let yesterday = today - chrono::Duration::days(1);

    lookup_cdb(
        &cdb::CDB::open(format!("files/ram/journal-cdb/{}.cdb", today.timestamp())),
        &hash.0,
    )
    .or(lookup_cdb(
        &cdb::CDB::open(format!("files/ram/journal-cdb/{}.cdb", yesterday.timestamp())),
        &hash.0,
    ))
    .or_else(|| {
        let lastchar = &hash.1[hash.1.len() - 1..];
        let cdb = cdb::CDB::open(format!("files/downloads/incoming/cdb/{lastchar}/{uid}.cdb"));
        lookup_cdb(&cdb, &hash.0).or(lookup_cdb(&cdb, &hash.1[1..]))
    }).or(fs::read_to_string(format!("files/ram/DB/{}.basetime", uid)).ok())
}

// fn write_to_cdb() -> () {
//     let mut cdb = (cdb::CDBWriter::create("./files/downloads/incoming/cdb/g/my-uid.cdb")).unwrap();
//     let _ = cdb.add(b"a/a8/my-uid-a80a5eed12b1e1e9bd9481b9d13800b1fc437e27-mountain.jpeg", b"hash-from-downloads-incoming-old");
//     let _ = cdb.finish();
// }

async fn req_handler(Query(QueryParams { uid }): Query<QueryParams>, uri: Uri) -> impl IntoResponse {
    // write_to_cdb();
    let mut headers = HeaderMap::new();
    let md5 = lookup_md5(&uid, uri.path());
    let json_response = Json(json!({ "md5": md5 }));
    headers.insert("X-aanewmd5", md5.unwrap_or_default().parse().unwrap());

    (headers, json_response)
}
