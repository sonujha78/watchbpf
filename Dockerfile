# ---- Build stage ----
FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y clang llvm libbpf-dev linux-headers-generic

WORKDIR /build
COPY . .

# eBPF programs compile karo
RUN cd bpf && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c execve.bpf.c -o execve.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c openat.bpf.c -o openat.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c connect.bpf.c -o connect.bpf.o && \
    cp *.bpf.o ../internal/embedded/

# Go binary build karo (embedded .o files ke saath)
RUN go build -o /watchbpf-agent ./cmd/watchbpf-agent

# ---- Runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y nftables ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /watchbpf-agent /usr/local/bin/watchbpf-agent

ENTRYPOINT ["/usr/local/bin/watchbpf-agent"]
CMD ["-mode=filter", "-state=/etc/watchbpf/baseline.json", "-enforce=dry-run"]
