package embedded

import _ "embed"

//go:embed execve.bpf.o
var ExecveObj []byte

//go:embed openat.bpf.o
var OpenatObj []byte

//go:embed connect.bpf.o
var ConnectObj []byte

//go:embed prompt_v1.txt
var PromptV1 string
