/*the code is designed to parse apache log files in a consistent manner with pipeline.yaml 
(https://github.com/elastic/beats/blob/main/filebeat/module/apache/access/ingest/pipeline.yml)
*/
#![allow(unused_imports)]
#![allow(dead_code)]//
//#![allow(unused_variables)]
use std::env;
use opensearch::{http::request::JsonBody, BulkParts};
use serde_json::{json, Value, Map};
use uaparser::UserAgentParser;
use maxminddb::Reader;
mod lru;
mod grok;
use lru::LruCache;
use std::num::NonZeroUsize;
use tokio::sync::{mpsc, oneshot };
use tokio::io::{AsyncReadExt, BufReader};
use tokio_util::io::StreamReader;
use futures::TryStreamExt;
mod parse_functions;
use minio_rsc::types::args::ObjectArgs;
use reqwest::Response;
use async_compression::tokio::bufread::GzipDecoder;
//the variable to control the size of chunks to send to opensearch

mod variables;
use variables::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    load_env_vars();

    let _ = CITY_READER.set(
        Reader::open_readfile(&env::var("CITY_READER_PATH").unwrap()).unwrap()
    );
    let _ = ASN_READER.set(
        Reader::open_readfile(&env::var("ASN_READER_PATH").unwrap()).unwrap()
    );
    let _ = PARSER_UA.set(
        UserAgentParser::from_yaml(&env::var("PARSER_UA_PATH").unwrap())
            .expect("Parser creation failed")
    ).unwrap();

    //zip_chunk_reader().await?;

    let result = process_log_file_minio().await;
    match result {
        Ok(()) => println!("successfully retrieved and parsed the file"),
        Err(e) => println!("some issue has occured {e}"),
    }

    Ok(())
}






pub async fn process_log_file_minio () -> Result<(), Box<dyn std::error::Error>> {

    let mut chunk_receiver;
    let file_reader;
    let response_option = get_minio_object().await?;
    let opensearch_client = setup_opensearch_client().await?;
    let mut decoder;
    if let Some(response) = response_option {
        // Convert the response body into a stream of bytes
        let body = response.bytes_stream();

        // Convert the stream into an AsyncRead
        let reader = StreamReader::new(body.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));

        // Wrap the AsyncRead in a BufReader
        let buffered_reader = BufReader::new(reader);

        // Create a GzipDecoder from the BufReader
        decoder = GzipDecoder::new(buffered_reader);
    } else {
        println!("Cannot download file as no such object exists");
        std::process::exit(0);
    }

    {
        let (chunk_sender, receiver_from_reader) = mpsc::channel(*CORE_NUM as usize);
        chunk_receiver = receiver_from_reader;

        file_reader = tokio::spawn(async move {
//  /home/myrza/Desktop/logFiles/testForRustLogs/60k.log

            // Create a buffer to hold each chunk of decompressed data
            let mut buffer = vec![0; 3000000]; 
            let mut line_buffer = String::new();
            let mut buffer_chunk = Vec::new();

            loop {
                let len = decoder.read(&mut buffer).await;
                match len {
                    Ok(0) => {
                        break;
                    }
                    Err(e) => {
                        println!("error occured while decoding : {e}");
                    }
                    _ => {

                    }
                }
                let chunk_capacity = *BUFFER_TO_READ_NUM_OF_LINES as usize;
                for byte in buffer.iter() {
                    let temp  = *byte as char;
                    if temp == '\n' {
                        //println!("{}", line_buffer);
                        buffer_chunk.push(line_buffer);
                        line_buffer = String::new();
                    }
                    else {
                        line_buffer.push(temp);
                    }
                    if buffer_chunk.len() == chunk_capacity {
                       
                        match chunk_sender.send(buffer_chunk).await {
                            Ok(()) => {
                            }
                            _ => {
                                println!("reader failed to send chunk");
                            }
                        };
             //           println!("reader sent the batch");
                        buffer_chunk = Vec::with_capacity(chunk_capacity);
                    }
                }



            }
            if !buffer_chunk.is_empty() {
                match chunk_sender.send(buffer_chunk).await {
                    Ok(()) => {
                    }
                    _ => {
                        println!("failed the last chunk from reader");
                    }
                };
               
            }
     
        });
    }
    let mut producer_vec = Vec::new();
    let mut receiver;
    let producers :tokio::task::JoinHandle<()>;
    { 
        let (sender, rcv) = mpsc::channel(*SENDER_CHANNEL_SIZE as usize);
        //let (sender, rcv) = oneshot::channel();
        receiver = rcv;
        producers = tokio::spawn(async move {
            while let Some(buffer_chunk) = chunk_receiver.recv().await {
                let batch_size = *BATCH_TO_SEND_NUM_OF_LINES as usize;
                let sender_clone = sender.clone();
                let _producer = tokio::spawn(async move {
                    let size = 500;
                    let mut ua_cache: LruCache<String, parse_functions::UserAgentParts> = LruCache::new(NonZeroUsize::new(size).unwrap());
                    let mut geoip_cache: LruCache<String, parse_functions::GeoipParts> = LruCache::new(NonZeroUsize::new(size).unwrap());
                    let mut batch = Vec::with_capacity(batch_size);
                    let mut offset: usize = 0;
                    for element in buffer_chunk {
                        let log_data = parse_functions::parse_common_log_entry(&element, &offset, &mut ua_cache, &mut geoip_cache).await;
                        let json_body: JsonBody<Value> = JsonBody::new(log_data);
                        batch.push(json_body);
                        if batch.len() >= batch_size {
                            
                            match sender_clone.send(batch).await {
                                Ok(()) => {
                                    
                                },
                                _ => {
                                    println!("parser failed the batch");
                                },
                            }
                            batch = Vec::with_capacity(batch_size);
                        }
                        offset += batch.len();
                    }
                    if !batch.is_empty() {

                        match sender_clone.send(batch).await {
                            Ok(()) => {

                            },
                            _ => {
                                println!("parser failed the last batch");
                            },
                        }
                    }
                });
                producer_vec.push(_producer);
                if producer_vec.len() > *CORE_NUM as usize {
                    (_, _, producer_vec) = futures::future::select_all(producer_vec).await;
                } 
            }
            while producer_vec.len() > 0 {
                (_, _, producer_vec) = futures::future::select_all(producer_vec).await;
            } 
        });
    } 
    
    let mut consumers_vec = Vec::new(); 
    // Start the consumers.

    let ind_name = INDEX_NAME.to_string();
    let consumers = tokio::spawn(async move {
        
        while let Some(batch_to_send) = receiver.recv().await {
            let client_clone_new = opensearch_client.clone();
            let ind_name = ind_name.clone();
            let _consumer = tokio::spawn(async move {
                
                let body: Vec<JsonBody<_>> = batch_to_send.into_iter().flat_map(|json_body| {
                    vec![json!({"index": {}}).into(), json_body]
                }).collect();

                let response =   client_clone_new
                .bulk(BulkParts::Index(&ind_name))
                .body(body)
                .send().await;

                match response {
                    Ok(returned) => {
                        if returned.status_code().is_success() {

                        } 
                        else {
                            println!("failed to send : {}", returned.status_code());
                        }                                         
                    },
                    Err(_e) => {
                        println!("too many requets or other server issue: {}", _e);                    
                    },
                }
            });
           
            consumers_vec.push(_consumer);
            if consumers_vec.len() == *SENDER_CHANNEL_SIZE as usize {
                (_, _, consumers_vec) = futures::future::select_all(consumers_vec).await;
            }    
        }
        while consumers_vec.len() > 0 {
            (_, _, consumers_vec) = futures::future::select_all(consumers_vec).await;
        } 

    });

   
    match tokio::join!(file_reader, consumers, producers) {
        (Ok(()), Ok(()), Ok(())) => {
            // All futures completed successfully
        },
        (Err(file_reader_error), consumers_result, producers_result) => {
            // file_reader failed
            println!("file_reader failed: {:?}, consumers: {:?}, producers: {:?}", file_reader_error, consumers_result, producers_result);
        },
        (file_reader_result, Err(consumers_error), producers_result) => {
            // consumers failed
            println!("file_reader: {:?}, consumers failed: {:?}, producers: {:?}", file_reader_result, consumers_error, producers_result);
        },
        (file_reader_result, consumers_result, Err(producers_error)) => {
            // producers failed
            println!("file_reader: {:?}, consumers: {:?}, producers failed: {:?}", file_reader_result, consumers_result, producers_error);
        },
    }


    
    Ok(())
}


/*
author: Belekov Myrzabek
version: 1.0
purpose: Takes minio server, bucket and object names as arguments and returns a .gz reader which can be used to read the file in chunks.
*/
async fn get_minio_object () -> Result<Option<Response>,Box<dyn std::error::Error>> 
{

    let bucket_name = &*MINIO_BUCKET;
    let object_name = &*MINIO_OBJECT;
    let args = ObjectArgs::new(bucket_name, object_name);
    let minio_client = setup_minio_client().await?;
    let exists = minio_client.bucket_exists(bucket_name).await;

    match exists {
        Ok(true) => println!("Bucket {} exists.", bucket_name),
        Ok(false) => {
            println!("Bucket {} does not exist.", bucket_name); std::process::exit(0)
        },
        Err(e) => {
            eprintln!("Error checking if bucket exists: {:?}", e);
            std::process::exit(0)
        }
    }


    let result = minio_client.get_object(args).await;
    let response_option: Option<Response>;

    match result {
        Ok(res) => response_option = Some(res),
        _ => {
            response_option = None;
        }
    }

    Ok (response_option)
}
//part realted to .gz
