ebpf-rerouter: rerouter.go
	go build -o $@

rerouter.go: pid_finder.go
rerouter.go: rerouter_x86_bpfel.go

rerouter_x86_bpfel.%: rerouter.ebpf.c
	go generate

rerouter.ebpf.c: bpf-amd64.h bpf-builtin.h bpf-utils.h
	@

clean:
	rm ebpf-rerouter rerouter_*bpf*.go *.o