ebpf-rerouter: app.go
	go build -o $@

app.go: rerouter.go bypass.go
	@touch $@

rerouter.go: pid_finder.go
rerouter.go: rerouter_x86_bpfel.go
	@touch $@

rerouter_x86_bpfel.go: rerouter_x86_bpfel.o
rerouter_x86_bpfel.o: rerouter.ebpf.c
	go generate

rerouter.ebpf.c: bpf-amd64.h bpf-builtin.h bpf-utils.h
	@touch $@

clean:
	rm -f ebpf-rerouter rerouter_*bpf*.go *.o