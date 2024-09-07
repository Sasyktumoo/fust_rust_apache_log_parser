# Rust_apache_log_parser

The 20k / sec apache log parser that parses and uploads to opensearch clutser, and also to AWS s3 bucket



#IMPORTANT!:
**1.Run the code with --release** feature, it significantly improve speed, (mine went from 2000 log lines/second to 6000 log lines/ second)

**2.Run through command line, index name needs to be specified right after the program name (as argv[1])**

**3.Then through stdin specify one by one the filepath for log files**

**4.Type 'changeindex' to change** the index to send ingested logs to

**5.Type 'exit' to stop** the program
