pub mod akamai_auth {
    use std::time::{SystemTime, UNIX_EPOCH};

    // use hmac::{Hmac, Mac};
    use regex::{Captures, Regex};
    use ring::hmac;
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
                    let start = SystemTime::now();
                    let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
                    options.start_time = Some(since_the_epoch.as_secs());
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
