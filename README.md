# ssm

SSM is a Software Security Module compared to Hardware Security Module.

Its API simulates Thales Payshield 9000.

# Limitation
```sh
1 set LMK only
Double length Key Only
4 Bytes Header only
All activities are authorized
small set of commands supported
```

# Dependency Installation
```sh
# npm install @shenyan1206/dukpt --save
(this will download other two dependency automatically: @shenyan1206/crypto-heler, @shenyan1206/buffer-helper)
```

# Commands Supported

Please check wiki page for the latest info or check the host_commands/ folder in source code

# Design summary
```sh
index.js: the entry point, it creates a socket server to receive data from client, and write response into socket back to client, check data integrity, then pass to ssmservice.js to handle.

ssmservice.js: first round of parsing. read header and command code, then pass to respetive command handler to process.

host_commands folder: it contains all command handler.

AO.js: one example of command handler. when processing, it does 3 things: parsing, processing, format output & return.

LMKManager.js: generate/load LMK when service started, and manage all interaction with LMK, such decrypt/encrypt a key under LMK pair.

lmk.txt: it contains 40 blocks of LMK. the default data is identical to Thales Test LMK. For production use, pls remove this file when deploy, it will be auto generated randomly.
```