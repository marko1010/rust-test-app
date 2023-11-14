pub mod utility {
    use std::{path::Path, fs, io};

    use chrono::Utc;
    use sha1::{Digest, Sha1};

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

    pub fn lookup_md5(uid: &str, path: &str) -> Option<String> {
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
            if let Ok(md5) = fs::read_to_string(format!("files/ram/DB/{}.basetime", uid)) {
                return Some(md5.replace("\r\n", "").replace("\n", ""));
            } else {
                return None;
            }
        })
    }
}

pub mod akamai_auth {
    use std::{
        collections::HashMap,
        time::{SystemTime, UNIX_EPOCH},
    };

    use hyper::Uri;
    // use hmac::{Hmac, Mac};
    use regex::{Captures, Regex};
    use ring::hmac;
    use url::Url;
    use urlencoding::encode;

    #[derive(Debug)]
    pub enum Algorithm {
        SHA256,
        SHA1,
        MD5,
    }

    #[derive(Debug)]
    pub struct AuthOptions {
        pub start_time: Option<u64>,
        pub end_time: Option<u64>,
        pub escape_early: bool,
        pub window_seconds: Option<u64>,
        pub verbose: bool,
        pub ip: Option<String>,
        pub session_id: Option<String>,
        pub payload: Option<String>,
        pub salt: Option<String>,
        pub algorithm: Algorithm,
        pub field_delimiter: char,
        pub acl_delimiter: char,
        pub token_type: Option<String>,
        pub token_name: Option<String>,
        pub key: String,
    }

    pub struct EdgeAuth {
        pub options: AuthOptions,
    }

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

    pub struct VerificationStatus {
        pub valid: bool,
        pub message: Option<&'static str>
    }

    pub fn verify_request(secret: &str, uri: &Uri) -> VerificationStatus {
        const TOKEN_NAME: &str = "__token__";
        const FIELD_DELIMITER: char = '~';
        const ACL_DELIMITER: char = '!';

        let url = Url::parse(&format!("http://localhost{}", uri.to_string())).unwrap();
        let hash_query: HashMap<_, _> = url.query_pairs().into_owned().collect();

        let token_string = hash_query.get(TOKEN_NAME);

        if token_string.is_none() {
            return VerificationStatus { valid: false, message: Some("Token is missing") };
        }

        let token_params = parse_token(token_string.unwrap(), FIELD_DELIMITER);

        let mut ea = EdgeAuth {
            options: AuthOptions {
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
            },
        };

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if ea.options.start_time.is_some() && ea.options.start_time.unwrap() > current_time {
            return VerificationStatus { valid: false, message: Some("Token not valid yet") };
        }

        if ea.options.end_time.is_some() && ea.options.end_time.unwrap() < current_time {
            return VerificationStatus { valid: false, message: Some("Token expired") };
        }

        let result = ea.verify_token(token_string.unwrap(), uri.path(), false);
        VerificationStatus { valid: result, message: if result { None } else { Some("Invalid token") } }
    }

    fn escape_early(text: &str) -> String {
        let encoded = encode(text).into_owned();

        let re = Regex::new("(~|'|*|%..)").unwrap();
        let result = re.replace_all(&encoded, |cap: &Captures| match &cap[0] {
            "~" => "%7e".to_string(),
            "'" => "%27".to_string(),
            "*" => "%2a".to_string(),
            _ => (&cap[0]).to_lowercase(),
        });

        result.into_owned()
    }

    impl EdgeAuth {
        pub fn generate_token(&mut self, path: &str, is_url: bool) -> String {
            let options = &mut self.options;
            if options.end_time.is_none() {
                if options.window_seconds.is_none() {
                    panic!("You must provide end_time or window_seconds.");
                }

                if options.start_time.is_none() {
                    let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    options.start_time = Some(since_the_epoch);
                }
                options.end_time =
                    Some(options.start_time.unwrap() + options.window_seconds.unwrap());
            }

            if options.start_time.is_some()
                && (options.end_time.unwrap() < options.start_time.unwrap())
            {
                panic!("Token will have already expired");
            }

            if options.verbose {
                println!("Akamai Token Generation Parameters");
                println!("{}: {}", if is_url { "URL" } else { "ACL" }, path);
                println!("Options: {:?}", options);
            }

            let mut new_token: Vec<String> = vec![];

            if options.ip.is_some() {
                new_token.push(format!("ip={}", options.ip.as_ref().unwrap()));
            }

            if options.start_time.is_some() {
                new_token.push(format!("st={}", options.start_time.unwrap()));
            }

            new_token.push(format!("exp={}", options.end_time.unwrap()));

            if is_url {
                new_token.push(format!(
                    "url={}",
                    if options.escape_early {
                        escape_early(path)
                    } else {
                        path.to_string()
                    }
                ));
            } else {
                new_token.push(format!("acl={}", path));
            }

            if options.session_id.is_some() {
                new_token.push(format!(
                    "id={}",
                    if options.escape_early {
                        escape_early(&options.session_id.as_ref().unwrap())
                    } else {
                        options.session_id.as_ref().unwrap().to_string()
                    }
                ));
            }

            if options.payload.is_some() {
                new_token.push(format!(
                    "data={}",
                    if options.escape_early {
                        escape_early(&options.payload.as_ref().unwrap())
                    } else {
                        options.payload.as_ref().unwrap().to_string()
                    }
                ));
            }

            let mut hash_source = new_token.clone();

            if options.salt.is_some() {
                hash_source.push(format!("salt={}", options.salt.as_ref().unwrap()));
            }

            let hmac_algorithm = match options.algorithm {
                Algorithm::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                Algorithm::SHA256 => hmac::HMAC_SHA256,
                Algorithm::MD5 => hmac::HMAC_SHA256,
            };

            let key = hmac::Key::new(hmac_algorithm, options.key.as_bytes());

            let delimiter = options.field_delimiter.to_string();
            let tag = hmac::sign(&key, hash_source.join(&delimiter).as_bytes());
            new_token.push(format!("hmac={}", hex::encode(tag.as_ref())));
            new_token.join(&delimiter)
        }

        pub fn verify_token(&mut self, token: &str, path: &str, is_url: bool) -> bool {
            let generated_token = self.generate_token(&path, is_url);
            println!("generated token: {}", generated_token);
            generated_token == token
        }
    }
}
