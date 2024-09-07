# Rust_apache_log_parser

This the version 4.0 which reads one file and processes logs concurrently, that is the file is being read in buffer chunks, and while sending and parser parse and vice versa. Command line arguments were removed, change environmental variables inside environmental_vars.env.



#IMPORTANT!:
**1.Run the code with --release** feature, it significantly improve speed, (mine went from 2000 log lines/second to 6000 log lines/ second)

**2.Run through command line, index name needs to be specified right after the program name (as argv[1])**

**3.Then through stdin specify one by one the filepath for log files**

**4.Type 'changeindex' to change** the index to send ingested logs to

**5.Type 'exit' to stop** the program
