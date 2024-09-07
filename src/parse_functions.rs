use chrono::DateTime;
use url::{Url, ParseError};
use uaparser::Parser;
use maxminddb::geoip2;
use std::net::IpAddr;
use std::str::FromStr;
use serde_json::{Map, Value};
use once_cell::sync::OnceCell;
use maxminddb::Reader;
use crate::grok::Matches;
use crate::lru;
use lru::LruCache;
use chrono::{Utc, Local, TimeZone};

use crate:: {
    CITY_READER, ASN_READER, PARSER_UA, COMPILED_PATTERNS, 
    FILESET_NAME, GEOIP_KEYS, UA_KEYS, URI_KEYS
};




//the below struct is needed for lru caching for user_agent, the fn user_agent_parse explains further
pub struct UserAgentParts {
    pub ua_name: String,
    pub ua_version: String,
    pub os_name: String,
    pub os_version: String,
    pub os_full: String,
    pub device_name: String,
}
//fixzone
pub struct GeoipParts<'a> {
    pub continent_name: &'a str,
    pub country_name: &'a str,
    pub country_iso_code: &'a str,
    pub city_name: &'a str,
    pub region_iso_code: &'a str,
    pub region_name: &'a str,
    pub location_lat: Option<f64>,
    pub location_lon: Option<f64>,
    pub as_number: Option<u32>,
    pub as_organization_name: &'a str,
}
impl<'a> Default for GeoipParts<'a> {
    fn default() -> Self {
        GeoipParts {
            continent_name: "",
            country_name: "",
            country_iso_code: "",
            city_name: "",
            region_iso_code: "",
            region_name: "",
            location_lat: None,
            location_lon: None,
            as_number: None,
            as_organization_name: "",
        }
    }
}

pub fn set_apache_specific_fields(json_map_ref: &mut Map<String, Value>) {
    map_insert(json_map_ref, "event.dataset", &format!("apache.{}", FILESET_NAME));
    map_insert(json_map_ref, "event.module", "apache");
    map_insert(json_map_ref, "fileset.name", FILESET_NAME);
    map_insert(json_map_ref, "service.type", "apache");
    map_insert(json_map_ref, "input.type", "log");

    
}

pub fn set_timestamp(json_map_ref: &mut Map<String, Value>, apache_time: &str) {
    //tries to change the format of the apache_time
    let parse_result = DateTime::parse_from_str(apache_time, "%d/%b/%Y:%H:%M:%S %z");
    
    //if format change is successful, applies the change, otherwise @timestamp will just copy the apache.access.time field
    match parse_result {
        Ok(parsed_datetime) => {
            let formatted_timestamp = parsed_datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            map_insert(json_map_ref, "@timestamp", formatted_timestamp.as_str());
        }
        _ => {
            map_insert(json_map_ref, "@timestamp", apache_time);
        }
    }


}


//parses the ssl.protocol field
pub fn set_tls_version_and_protocol(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches) {
    if let Some(protocol) = parsed_apache.get("apache.access.ssl.protocol") {
        let protocol_lowercase = protocol.to_lowercase();
        let parts: Vec<&str> = protocol_lowercase.split('v').collect();
        if parts.len() == 2 {
            let version = if parts[1].contains('.') {
                parts[1].to_string()
            } else {
                format!("{}.0", parts[1])
            };
            map_insert(json_map_ref,  "tls.version", &version);
            map_insert(json_map_ref,  "tls.version_protocol", parts[0]);
        }
    }
}

pub fn set_cipher(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches) {
    if let Some(cipher) = parsed_apache.get("apache.access.ssl.protocol") {
        map_insert(json_map_ref, &"tls.cipher".to_string(), &cipher.to_string());
    }
}
//testzone2
//I used maximindb library and documentation to parse the  and asn
pub fn parse_geoip(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches, cache: &mut LruCache<String, GeoipParts>) {

    let source_ip: &str;
    if let Some(source_ip_value) = parsed_apache.get("source.ip") {
        source_ip = source_ip_value;
    }
    else if let Some(source_ip_value) = parsed_apache.get("source.address")  {
        source_ip = source_ip_value;
    }
    else {
        return;
    }

    if source_ip == "-" {
        return;
    }
    //might be error, needs handling
    let ip: IpAddr;

    if let Ok(correct_ip) = FromStr::from_str(source_ip) {
        // Handle the case when the IP address is successfully parsed.
        ip = correct_ip;

    } else {
        // Handle the case when the IP address parsing fails.
        return;
    }
    
    if let Some(cached_data) = cache.get(source_ip) {
        // Use cached data
        if !cached_data.continent_name.is_empty() {
            map_insert(json_map_ref, GEOIP_KEYS[0], cached_data.continent_name);
        }
        if !cached_data.country_name.is_empty() {
            map_insert(json_map_ref, GEOIP_KEYS[1], cached_data.country_name);
        }
        if !cached_data.country_iso_code.is_empty() {
            map_insert(json_map_ref, GEOIP_KEYS[2], cached_data.country_iso_code);
        }
        if !cached_data.city_name.is_empty() {
            map_insert(json_map_ref, GEOIP_KEYS[3], cached_data.city_name);
        }
        if !cached_data.region_iso_code.is_empty() {
            map_insert(json_map_ref, GEOIP_KEYS[4], cached_data.region_iso_code);
        }
        if !cached_data.region_name.is_empty() {
            map_insert(json_map_ref, GEOIP_KEYS[5], cached_data.region_name);
        }
        if cached_data.location_lat.is_some() {
            map_insert(json_map_ref, GEOIP_KEYS[6], cached_data.location_lat.unwrap().to_string().as_str());
        }
        if cached_data.location_lon.is_some() {
            map_insert(json_map_ref, GEOIP_KEYS[7], cached_data.location_lon.unwrap().to_string().as_str());
        }
        if cached_data.as_number.is_some() {
            map_insert(json_map_ref, "source.as.number", cached_data.as_number.unwrap().to_string().as_str());
        }
        if !cached_data.as_organization_name.is_empty() {
            map_insert(json_map_ref, "source.as.organization.name", cached_data.as_organization_name);
        }
    }
    else {
        let reference: &OnceCell<Reader<Vec<u8>>> = &CITY_READER;
        let city_result = reference.get().unwrap().lookup::<geoip2::City>(ip);

        //let city_result: Result<geoip2::City, maxminddb::MaxMindDBError> = CITY_READER.lookup(ip);
        
        let mut geoip_parts: GeoipParts = Default::default();
        match city_result {
            
            Ok(city) => {
                
                if let Some(continent) = city.continent {
                    if let Some(names) = continent.names {
                        if let Some(name) = names.get("en") {
                            map_insert(json_map_ref, GEOIP_KEYS[0], name);
                            geoip_parts.continent_name = name;
                        }
                    }
                }
                
                if let Some(country) = city.country {
                    if let Some(names) = country.names {
                        if let Some(name) = names.get("en") {
                            map_insert(json_map_ref, GEOIP_KEYS[1], name);
                            geoip_parts.country_name = name;
                        }
                    }
                    if let Some(iso_code) = country.iso_code {
                        map_insert(json_map_ref, GEOIP_KEYS[2], iso_code);
                        geoip_parts.continent_name = iso_code;
                    }
                }
                
                if let Some(city) = city.city {
                    if let Some(names) = city.names {
                        if let Some(name) = names.get("en") {
                            map_insert(json_map_ref, GEOIP_KEYS[3], name);
                            geoip_parts.city_name = name;
                        }
                    }
                }
                
                if let Some(subdivisions) = &city.subdivisions {
                    if let Some(subdivision) = subdivisions.get(0) {
                        if let Some(iso_code) = &subdivision.iso_code {
                            map_insert(json_map_ref, GEOIP_KEYS[4], iso_code);
                            geoip_parts.region_iso_code = iso_code;
                        }
                        if let Some(names) = &subdivision.names {
                            if let Some(name) = names.get("en") {
                                map_insert(json_map_ref, GEOIP_KEYS[5], name);
                                geoip_parts.region_name = name;
                            }
                        }
                    }
                }
         
                if let Some(location) = city.location {
                    if let Some(latitude) = location.latitude {
                        map_insert(json_map_ref, GEOIP_KEYS[6], latitude.to_string().as_str());
                        geoip_parts.location_lat = Some(latitude);
                    }
                    if let Some(longitude) = location.longitude {
                        map_insert(json_map_ref, GEOIP_KEYS[7], longitude.to_string().as_str());
                        geoip_parts.location_lon = Some(longitude);
                    }
                }
            }
            Err(_error) =>{
                //println!("failed to find location with this ip {:?}", error);
            }
        }

        
        let asn_result = ASN_READER.get().unwrap().lookup::<geoip2::Asn>(ip);
        
        match asn_result {
            Ok(asn) => {
                if let Some(num) = asn.autonomous_system_number {
                    map_insert(json_map_ref, "source.as_number", num.to_string().as_str());
                    geoip_parts.as_number= Some(num);
                }
                if let Some(organization) = asn.autonomous_system_organization {
                    map_insert(json_map_ref, "source.as.organization_name", organization);
                    geoip_parts.as_organization_name= organization;
                }
            }
            Err(_error) =>{
                //println!("failed to find asn with this ip {:?}", error);
            }
        }
        cache.put(source_ip.to_string(), geoip_parts);
    }




}
//the user_agent field unlike url does not conform to any standards and companies are free to define user_agent however they want
//so every log line the whole regex.yaml has to be scanned which is too lengthy
//lru caching library was used to speed up the process, adjacent log lines tend to be the same, so lru speeds up the process greatly
//testzone
pub fn user_agent_parse(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches, cache: &mut LruCache<String, UserAgentParts>) {

    let user_agent_line: &str;
    if let Some(ua_line) = parsed_apache.get("user_agent.original") {
        user_agent_line = ua_line;
        map_insert(json_map_ref, UA_KEYS[6], user_agent_line);
    }
    else {
        return;
    };

    if user_agent_line == "-" {
        map_insert(json_map_ref, UA_KEYS[0], "Other");
        map_insert(json_map_ref, UA_KEYS[1], "Other");
        return
    }
    
    if let Some(cached_result) = cache.get(user_agent_line) {
        //if cache found

        map_insert(json_map_ref, UA_KEYS[0], &cached_result.ua_name);
        map_insert(json_map_ref, UA_KEYS[1], &cached_result.device_name);
        if !cached_result.ua_version.is_empty() {
            map_insert(json_map_ref, UA_KEYS[2], &cached_result.ua_version);
        }
        if !cached_result.ua_version.is_empty() {
            map_insert(json_map_ref, UA_KEYS[3], &cached_result.os_name);
        }
        if !cached_result.os_version.is_empty() {
            map_insert(json_map_ref, UA_KEYS[4], &cached_result.os_version);
        }

        if !cached_result.os_full.is_empty() {
            map_insert(json_map_ref, UA_KEYS[5], &cached_result.os_full);
        }
    }
    else {
        let client = PARSER_UA.get().unwrap().parse(&user_agent_line);
        let mut holder = UserAgentParts {
            ua_name: String::new(),
            ua_version: String::new(),
            os_name: String::new(),
            os_version: String::new(),
            os_full: String::new(),
            device_name: String::new(),
        };
        let ua_name = client.user_agent.family.to_string();
        map_insert(json_map_ref, UA_KEYS[0], &ua_name);
    
        // below for target_field.user_agent
        let ua_major = client.user_agent.major.unwrap_or_default();
        let ua_minor = client.user_agent.minor.unwrap_or_default();
        let ua_patch = client.user_agent.patch.unwrap_or_default();
    
        let mut ua_version = ua_major.to_string();
    
        if !ua_minor.is_empty() {
            ua_version.push_str(&format!(".{}", ua_minor));
        }
    
        if !ua_patch.is_empty() {
            ua_version.push_str(&format!(".{}", ua_patch));
        }
    
        if !ua_version.is_empty() {
            map_insert(json_map_ref, UA_KEYS[1], &ua_version);
        }
    
        // below is for target_field.os
        let os_name = client.os.family.to_string();
        if client.os.family.to_string() != "Other" {
            map_insert(json_map_ref, UA_KEYS[2], &os_name);
        }
        let os_major = client.os.major.unwrap_or_default();
        let os_minor = client.os.minor.unwrap_or_default();
        let os_patch = client.os.patch.unwrap_or_default();
    
        let mut os_version = os_major.to_string();
    
        if !os_minor.is_empty() {
            os_version.push_str(&format!(".{}", os_minor));
        }
    
        if !os_patch.is_empty() {
            os_version.push_str(&format!(".{}", os_patch));
        }
    
        if !os_version.is_empty() {
            map_insert(json_map_ref, UA_KEYS[3], &os_version);
        }
    
        let os_full = format!("{} {}", client.os.family, os_version);
        if os_version.as_str() != ".." && client.os.family.to_string() != "Other" {
            map_insert(json_map_ref, UA_KEYS[4], &os_full);
        }
        let device_name = "Other".to_string();
        map_insert(json_map_ref, UA_KEYS[5], &device_name);
    
        holder.ua_name = ua_name;
        holder.ua_version = ua_version;
        holder.os_name = os_name;
        holder.os_version = os_version;
        holder.os_full = os_full;
        holder.device_name = device_name;

        cache.put(user_agent_line.to_string(), holder);
    }
    
    
//endf


}


pub fn parse_address(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches) {
    //let pattern = "^(%{IP:source.ip}|%{HOSTNAME:source.domain})$";

    if let Some(input) = parsed_apache.get("source.address") {
        if let Some(temp_parsed_apache) = COMPILED_PATTERNS[4].match_against(input) {

                if let Some(value) = temp_parsed_apache.get("source.ip") {
                    map_insert(json_map_ref, "source.ip", value);
                }
                else if let Some(value) = temp_parsed_apache.get("source.domain") {
                    map_insert(json_map_ref, "source.domain", value);
                }
               
        }
    }

}


pub fn set_domain(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches) {

    if parsed_apache.get("url.domain").is_none() && parsed_apache.get("destination.domain").is_some() {
        if let Some(domain_value) = parsed_apache.get("destination.domain") {
            map_insert(json_map_ref, "url.domain", domain_value);
        }
    }
}

pub fn insert_message(json_map_ref: &mut Map<String, Value>, input_message: &str) {
    //json_map_ref.insert("message".to_string(), Value::String(input_message.to_string()));
    //the above is better, but it might add some problems in the future
    map_insert(json_map_ref, "event.original", input_message);
}

pub fn set_event_outcome(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches) {
    if let Some(status_code_str) = parsed_apache.get("http.response.status_code") {
        if let Ok(num) = status_code_str.parse::<u16>() {
            if num < 400 {
                map_insert(json_map_ref, "event.outcome", "success");
            } else {
                map_insert(json_map_ref, "event.outcome", "failure");
            }
        }
    }
}

//parses the url, the url crate was used to parse it
pub fn uri_parts(json_map_ref: &mut Map<String, Value>, parsed_apache: &Matches) {

    let uri_line : &str;
    if let Some(uri) = parsed_apache.get("_tmp.url_orig") {
        uri_line = uri;
    }
    else {
        return;
    }

    let mut to_be_parsed_url: Option<Url> = None;
    match Url::parse(uri_line) {
        Ok(url) => {
            to_be_parsed_url = Some(url);

        }
        Err(ParseError::RelativeUrlWithoutBase) => {
            // Handle the error, e.g., log it or return a default value
            let base_url = Url::parse("testscheme://example.com").unwrap();
            let absolute_url = match base_url.join(uri_line) {
                Ok(url) => {
                    url
                }
                Err(_e) => {
                    ("Failed to join URL: {}", uri_line);
                    return
                }
            };
            to_be_parsed_url = Some(absolute_url);

        }
        Err(err) => {
            println!("You have error : {:?}", err);
        }
    }

    map_insert(json_map_ref, URI_KEYS[0], uri_line);
    let parsed_url = to_be_parsed_url.unwrap();
    let scheme = parsed_url.scheme();
    if scheme != "testscheme" {
        map_insert(json_map_ref, URI_KEYS[1], scheme);
    }
    
    map_insert(json_map_ref, URI_KEYS[2], parsed_url.path());
    
    if let Some(fragment) = parsed_url.fragment() {
        map_insert(json_map_ref, URI_KEYS[3], fragment);
    }
    if let Some(extension) = parsed_url
        .path_segments()
        .and_then(|segments| segments.last())
        .filter(|segment| segment.contains('.')) // Only consider segments with a dot
        .and_then(|segment| segment.split('.').last()) {
        map_insert(json_map_ref, URI_KEYS[4], extension);
    }
    if parsed_url.username() != "" {
        map_insert(json_map_ref, URI_KEYS[5], parsed_url.username());
    }
    if let Some(password) = parsed_url.password() {
        map_insert(json_map_ref, URI_KEYS[6], password);
        if parsed_url.username() != "" {
            map_insert(json_map_ref, URI_KEYS[7], &format!("{}:{}", parsed_url.username(), password));
        }
    }
    
    if let Some(port) = parsed_url.port() {
        map_insert(json_map_ref, URI_KEYS[8], &port.to_string());
    }
    
    if let Some(host) = parsed_url.host_str() {
        if host != "example.com" {
            map_insert(json_map_ref, URI_KEYS[9], host);
        }
    }
    if let Some(query) = parsed_url.query() {
        map_insert(json_map_ref, URI_KEYS[10], query);
    }
    
}

pub fn map_insert(json_map_ref: &mut Map<String, Value>, key: &str, value: &str) {
    //let mut json_map = Map::new();
    let mut current_map= json_map_ref;
    let parts: Vec<&str> = key.split('.').collect();

    for (i, part) in parts.iter().enumerate() {
        let tmp_part = part.to_string();
        if i == parts.len() - 1 {
            current_map.insert(tmp_part, Value::String(value.to_string()));
            break;
        }

        if !current_map.contains_key(&tmp_part) {
            current_map.insert(tmp_part.clone(), Value::Object(Map::new()));
        }

        if let Some(Value::Object(next_map)) = current_map.get_mut(&tmp_part) {
            current_map = next_map;
        } else {
            break;
        }
    }

}

pub fn convert_to_map(parsed_apache: &Matches, pattern_num: &i32) -> Map<String, Value> {

    let mut json_map = Map::new();

    match pattern_num {
        0 => {
            map_insert(&mut json_map, "destination.domain", parsed_apache.get("destination.domain").unwrap());
            map_insert(&mut json_map, "source.ip", parsed_apache.get("source.ip").unwrap());
            map_insert(&mut json_map, "user.name", parsed_apache.get("user.name").unwrap());
            
            if let Some(http_request_method) = parsed_apache.get("http.request.method") {
                map_insert(&mut json_map, "http.request.method", http_request_method);
            }
            
            if let Some(http_version) = parsed_apache.get("http.version") {
                map_insert(&mut json_map, "http.version", http_version);
            }
            
            map_insert(&mut json_map, "http.response.status_code", parsed_apache.get("http.response.status_code").unwrap());
            
            if let Some(http_response_body_bytes) = parsed_apache.get("http.response.body.bytes") {
                map_insert(&mut json_map, "http.response.body.bytes", http_response_body_bytes);
            }
            
            if let Some(http_request_referrer) = parsed_apache.get("http.request.referrer") {
                map_insert(&mut json_map, "http.request.referrer", http_request_referrer);
            }
        }
        1 => {
            map_insert(&mut json_map, "source.address", parsed_apache.get("source.address").unwrap());
            map_insert(&mut json_map, "user.name", parsed_apache.get("user.name").unwrap());
            
            if let Some(http_request_method) = parsed_apache.get("http.request.method") {
                map_insert(&mut json_map, "http.request.method", http_request_method);
            }
            
            if let Some(http_version) = parsed_apache.get("http.version") {
                map_insert(&mut json_map, "http.version", http_version);
            }
            
            map_insert(&mut json_map, "http.response.status_code", parsed_apache.get("http.response.status_code").unwrap());
            
            if let Some(http_response_body_bytes) = parsed_apache.get("http.response.body.bytes") {
                map_insert(&mut json_map, "http.response.body.bytes", http_response_body_bytes);
            }
            
            if let Some(http_request_referrer) = parsed_apache.get("http.request.referrer") {
                map_insert(&mut json_map, "http.request.referrer", http_request_referrer);
            }
        
        }
        2 => {
            map_insert(&mut json_map, "source.address", parsed_apache.get("source.address").unwrap());
            map_insert(&mut json_map, "user.name", parsed_apache.get("user.name").unwrap());
            map_insert(&mut json_map, "http.response.status_code", parsed_apache.get("http.response.status_code").unwrap());
        }
        3 => {
            map_insert(&mut json_map, "source.address", parsed_apache.get("source.address").unwrap());
            map_insert(&mut json_map, "apache.access.ssl.protocol", parsed_apache.get("apache.access.ssl.protocol").unwrap());
            map_insert(&mut json_map, "apache.access.ssl.cipher", parsed_apache.get("apache.access.ssl.cipher").unwrap());
            map_insert(&mut json_map, "http.request.method", parsed_apache.get("http.request.method").unwrap());
            map_insert(&mut json_map, "http.version", parsed_apache.get("http.version").unwrap());
            if let Some(http_response_body_bytes) = parsed_apache.get("http.response.body.bytes") {
                map_insert(&mut json_map, "http.response.body.bytes", http_response_body_bytes);
            }
        }
        _ => {

        }
    }

    json_map
}


pub async fn parse_common_log_entry(input: &str, offset: &usize, ua_cache: &mut LruCache<String, UserAgentParts>, geoip_cache: &mut LruCache<String, GeoipParts<'_>>) -> Value {

    //bool to determine whether any pattern matched
    let mut match_found = false;
    //the grok crate returns a type that is not modifiable, so I need to read in into the hashmap to make it modifiable
    //let mut hash_map_for_parsed_apache :HashMap<String,String> = HashMap ::new();
    let mut json_map_for_parsed_apache: Map<String, Value> = Map::new();
    let mut pattern_num = 0;
    for pattern in COMPILED_PATTERNS.iter().take(COMPILED_PATTERNS.len() - 1) {
            
            if let Some(parsed_apache) = pattern.match_against(input) {
 
                match_found = true;          
            
                json_map_for_parsed_apache = convert_to_map(&parsed_apache, &pattern_num);

                //the insertion of message field into hashmap to be consistent with filebeat
                insert_message(&mut json_map_for_parsed_apache, input);
                //the below are fields modifications to match the pipeline.yaml file for filebeat
                //adds the event.created field
                let creation: DateTime<Utc> = Utc::now();
                let create_timestamp = Local.from_utc_datetime(&creation.naive_utc());
                let formatted_timestamp_created = create_timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
                map_insert(&mut json_map_for_parsed_apache, "event.created", &formatted_timestamp_created);
                //parses the url part of the log
                uri_parts(&mut json_map_for_parsed_apache, &parsed_apache);
                set_domain(&mut json_map_for_parsed_apache, &parsed_apache);
                map_insert(&mut json_map_for_parsed_apache, "event.kind", "event");
                map_insert(&mut json_map_for_parsed_apache, "event.category", "web");
                set_event_outcome(&mut json_map_for_parsed_apache, &parsed_apache);
                //parses the source_up using the last pattern in grok that was declared in the beginning of the file
                parse_address(& mut json_map_for_parsed_apache, &parsed_apache);
   
                if let Some(apache_time) = parsed_apache.get("apache.access.time") {
                    set_timestamp(&mut json_map_for_parsed_apache, apache_time);
                };
                //parses user_agent using regexes.yaml and cache crate because of the nature of user_agent logs
                user_agent_parse(&mut json_map_for_parsed_apache,&parsed_apache, ua_cache);
                //parses the geoip and organization name using geolite2-city and geolit2-asn
                parse_geoip(&mut json_map_for_parsed_apache, &parsed_apache, geoip_cache);
                set_cipher(&mut json_map_for_parsed_apache, &parsed_apache);
                set_tls_version_and_protocol(&mut json_map_for_parsed_apache, &parsed_apache);


                //adds the event.ingested field
                let ingestion: DateTime<Utc> = Utc::now();
                let ingest_timestamp = Local.from_utc_datetime(&ingestion.naive_utc());
                let formatted_timestamp_ingested = ingest_timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(); 
                map_insert(&mut json_map_for_parsed_apache, "event.ingested", &formatted_timestamp_ingested);
                //adds the missing fields to match with filebeat yaml
                set_apache_specific_fields( &mut json_map_for_parsed_apache);
                map_insert(&mut json_map_for_parsed_apache, "log.offset", offset.to_string().as_str());
                break;
            }
    pattern_num += 1;
    }

    if !match_found {
        //if match was not found, the error.message field will be inserted
        
        map_insert(&mut json_map_for_parsed_apache, "error.message", "grokparsefailure");
        
    }

    Value::Object(json_map_for_parsed_apache)
}