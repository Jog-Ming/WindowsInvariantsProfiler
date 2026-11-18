package main

import _ "embed"

//go:embed assets/tracelog.exe
var tracelogData []byte

const tracelogSHA256 = "1c58f8a10a812aaa7119c5a17b3b16d7314fda744673d96b5df4edf0931b845d"
