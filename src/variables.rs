
use std::env;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use dotenv::dotenv;
use url::Url;
use opensearch::OpenSearch;
use opensearch::auth::Credentials;
use opensearch::{
    cert::CertificateValidation, http::transport::SingleNodeConnectionPool,
    http::transport::TransportBuilder, 
};
use opensearch::indices::IndicesCreateParts;
use minio_rsc::client::Minio;
use minio_rsc::provider::StaticProvider;
use maxminddb::Reader;
use uaparser::UserAgentParser;
use serde_json::json;
use crate::{grok, grok::Grok};



pub static INDEX_NAME: Lazy<String> = Lazy::new(|| {
    let mut args = env::args().skip(1); // Skip the first argument, which is the program name
    args.next().unwrap_or_else(|| String::new())
});

pub static MINIO_BUCKET: Lazy<String> = Lazy::new(|| {
    let mut args = env::args().skip(2); // Skip the first argument, which is the program name
    args.next().unwrap_or_else(|| String::new())
});
pub static MINIO_OBJECT: Lazy<String> = Lazy::new(|| {
    let mut args = env::args().skip(3); // Skip the first argument, which is the program name
    args.next().unwrap_or_else(|| String::new())
});



pub static FILESET_NAME :&str = "access";
pub static URL: Lazy<Url> = Lazy::new(|| {
    dotenv().ok();
    Url::parse(&env::var("OPENSEARCH_URL").unwrap_or_else(|_| String::new())).unwrap()
});

pub static CREDENTIALS: Lazy<Credentials> = Lazy::new(|| {
    dotenv().ok();
    Credentials::Basic(
        env::var("USERNAME_TO_SEND").unwrap_or_else(|_| String::new()),
        env::var("PASSWORD_TO_SEND").unwrap_or_else(|_| String::new())
    )
});

pub static MINIO_USERNAME: Lazy<String> = Lazy::new(|| {
    dotenv().ok();
    env::var("MINIO_USERNAME").unwrap_or_else(|_| String::new())
});
pub static MINIO_PASSWORD: Lazy<String> = Lazy::new(|| {
    dotenv().ok();
    env::var("MINIO_PASSWORD").unwrap_or_else(|_| String::new())
});
/*pub static BUCKET_MINIO: Lazy<String> = Lazy::new(|| {
    dotenv().ok();
    env::var("BUCKET_MINIO").unwrap_or_else(|_| String::new())
});
pub static INDEX_NAME: Lazy<String> = Lazy::new(|| {
    dotenv().ok();
    env::var("INDEX_NAME").unwrap_or_else(|_| String::new())
});
*/
pub static CORE_NUM: Lazy<i32> = Lazy::new(|| {
    dotenv().ok();
    env::var("CORE_NUM").unwrap_or_else(|_| String::new()).parse::<i32>().unwrap_or(0)
});

pub static BUFFER_TO_READ_NUM_OF_LINES: Lazy<i32> = Lazy::new(|| {
    dotenv().ok();
    env::var("BUFFER_TO_READ_NUM_OF_LINES").unwrap_or_else(|_| String::new()).parse::<i32>().unwrap_or(0)
});

pub static BATCH_TO_SEND_NUM_OF_LINES: Lazy<i32> = Lazy::new(|| {
    dotenv().ok();
    env::var("BATCH_TO_SEND_NUM_OF_LINES").unwrap_or_else(|_| String::new()).parse::<i32>().unwrap_or(0)
});
pub static READER_CHANNEL_SIZE: Lazy<i32> = Lazy::new(|| {
    dotenv().ok();
    env::var("READER_CHANNEL_SIZE").unwrap_or_else(|_| String::new()).parse::<i32>().unwrap_or(0)
});
pub static SENDER_CHANNEL_SIZE: Lazy<i32> = Lazy::new(|| {
    dotenv().ok();
    env::var("SENDER_CHANNEL_SIZE").unwrap_or_else(|_| String::new()).parse::<i32>().unwrap_or(0)
});

pub fn load_env_vars() {
    match dotenv::from_filename("environmental_vars.env") {
        Ok(_) => {
            println!("loaded environmental variables")
        }
        Err(_e) => {
            println!("failed to load environmental variables")
        }
    }
}

pub static CITY_READER: OnceCell<Reader<Vec<u8>>> = OnceCell::new();
pub static ASN_READER: OnceCell<Reader<Vec<u8>>> = OnceCell::new();
pub static PARSER_UA: OnceCell<UserAgentParser> = OnceCell::new();
//the feauters with default values, might change them
pub static URI_TARGET_FIELD : &str = "url";
pub static UA_TARGET_FIELD : &str = "user_agent";
pub static GEOIP_TARGET_FIELD : &str = "geoip";
pub static UA_KEYS: Lazy<Box<[&'static str]>> = Lazy::new(|| {
    let values = vec![
        Box::leak(format!("{}.name", UA_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.version", UA_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.os.name", UA_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.os.version", UA_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.os.full", UA_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.device.name", UA_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.original", UA_TARGET_FIELD).into_boxed_str()) as &'static str,
        // Add more values as needed
    ];

    values.into_boxed_slice()
});
pub static GEOIP_KEYS: Lazy<Box<[&'static str]>> = Lazy::new(|| {
    
    let values = vec![
        Box::leak(format!("source.{}.continent_name", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("source.{}.country_name", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("source.{}.country_iso_code", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("source.{}.city_name", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("source.{}.region_iso_code", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("source.{}.region_name", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("source.{}.location.lat", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("source.{}.location.lon", GEOIP_TARGET_FIELD).into_boxed_str()) as &'static str,
        // Add more values as needed
    ];
    
    values.into_boxed_slice()
});

pub static URI_KEYS: Lazy<Box<[&'static str]>> = Lazy::new(|| {
    let values = vec![
        Box::leak(format!("{}.original", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.scheme", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.path", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.fragment", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.extension", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.username", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.password", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.user_info", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.port", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.domain", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        Box::leak(format!("{}.query", URI_TARGET_FIELD).into_boxed_str()) as &'static str,
        // Add more values as needed
    ];

    values.into_boxed_slice()
});



//makes a connection with opensearch
pub async fn setup_opensearch_client() -> Result<OpenSearch, Box<dyn std::error::Error>> {
    let url = URL.clone();
    let credentials = CREDENTIALS.clone();
    let transport = TransportBuilder::new(SingleNodeConnectionPool::new(url))
        .cert_validation(CertificateValidation::None)
        .auth(credentials)
        .build()?;
    Ok(OpenSearch::new(transport))
}

pub async fn setup_minio_client() -> Result<Minio, Box<dyn std::error::Error>>  {
    let provider = StaticProvider::new("admin", "password", None);
    let minio = Minio::builder()
        .host("http://127.0.0.1:9000")
        .provider(provider)
        .secure(false)
        .build()
        .unwrap();
    Ok(minio)
}

//creates index in opensearch
#[allow(dead_code)]
async fn create_index(client: &OpenSearch) -> Result<(), Box<dyn std::error::Error>> {
        client
        .indices()
        .create(IndicesCreateParts::Index("name_index"))
        .body(json!({}))
        .send()
        .await?;
    Ok(())
}

//the global varibale to assign indexes
//the below is a parameter that needs to changed depending on the type log files, access or error log files
//the below is patterns for grok to match agaisnt,

//lazy crate will initialize itself only when it is called
//the below variable is a vector of grok patterns that will be used for parsing
pub static COMPILED_PATTERNS: Lazy<Vec<grok::Pattern>> = Lazy::new(|| {
    //the below is a vector of 5 patterns that will used for apache log parsing, the first 4 are from filebeat yaml and the last pattern will be needed for some other fn
    let patterns_str = vec![
        (r#"%{IPORHOST:destination.domain} %{IPORHOST:source.ip} - %{DATA:user.name} \[%{HTTPDATE:apache.access.time}\] "(?:%{WORD:http.request.method} %{DATA:_tmp.url_orig} HTTP/%{NUMBER:http.version}|-)?" %{NUMBER:http.response.status_code} (?:%{NUMBER:http.response.body.bytes}|-)( "%{DATA:http.request.referrer}")?( "%{DATA:user_agent.original}")?"#),
        (r#"%{IPORHOST:source.address} - %{DATA:user.name} \[%{HTTPDATE:apache.access.time}\] "(?:%{WORD:http.request.method} %{DATA:_tmp.url_orig} HTTP/%{NUMBER:http.version}|-)?" %{NUMBER:http.response.status_code} (?:%{NUMBER:http.response.body.bytes}|-)( "%{DATA:http.request.referrer}")?( "%{DATA:user_agent.original}")?"#),
        (r#"%{IPORHOST:source.address} - %{DATA:user.name} \[%{HTTPDATE:apache.access.time}\] "-" %{NUMBER:http.response.status_code} -"#),
        (r#"\[%{HTTPDATE:apache.access.time}\] %{IPORHOST:source.address} %{DATA:apache.access.ssl.protocol} %{DATA:apache.access.ssl.cipher} "%{WORD:http.request.method} %{DATA:_tmp.url_orig} HTTP/%{NUMBER:http.version}" (-|%{NUMBER:http.response.body.bytes})"#),
        ("^(%{IP:source.ip}|%{HOSTNAME:source.domain})$"),
    ];

    let mut compiled_patterns = Vec::new();
    let mut grok = Grok::with_default_patterns();
    for pattern in patterns_str {
        if let Ok(compiled_pattern) = grok.compile(pattern, false) {
            compiled_patterns.push(compiled_pattern);
        }
    }
    compiled_patterns
});