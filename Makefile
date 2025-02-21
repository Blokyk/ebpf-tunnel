TUNNEL ?= go
REROUTER ?= go
PREFIX ?= /usr/local

.PHONY: all rerouter tunnel install
all: rerouter tunnel

install: bin/ebpf-rerouter bin/proxy-tunnel
	install -t $(PREFIX)/bin $^

install-sd: install-rerouter install-tunnel

install-rerouter: ebpf-rerouter.service
	install -t /etc/systemd/system $<
	systemctl enable $<
install-tunnel: cntlm-tunnel.service
	install -t /etc/systemd/system $<
	systemctl enable $<

help:
	@echo 'Generic targets:'
	@echo '  - all'
	@echo '  - clean'
	@echo '  - install           Installs the rerouter and tunnel to the configured'
	@echo '                      prefix. Might require sudo.'
	@echo '  - install-rerouter  Installs '
	@echo '  - install-sd        Installs a sample systemd service file to use the installed'
	@echo '                      rerouter and tunnel. Might require sudo.'
	@echo
	@echo 'Development targets:'
	@echo '  - run-rerouter  Run the eBPF rerouter'
	@echo '  - run-tunnel    Run the tunnel'
	@echo
	@echo 'Available flags:'
	@echo '  - PREFIX        Directory used by `install` target [/usr/local]'
	@echo '  - REROUTER      Selects the rerouter variant (values: [go])'
	@echo '  - TUNNEL        Selects the tunnel variant (values: [go], c)'
	@echo '  - CC, CFLAGS    Usual C compilation variables'

rerouter: bin/ebpf-rerouter

run-rerouter: bin/ebpf-rerouter
	sudo bin/ebpf-rerouter run

bin/ebpf-rerouter: bin/$(REROUTER)-rerouter
	cp $< $@

.PHONY: go-rerouter/ebpf-rerouter
go-rerouter/ebpf-rerouter:
	$(MAKE) -C go-rerouter ebpf-rerouter
bin/go-rerouter: go-rerouter/ebpf-rerouter bin/
	cp $< $@

tunnel: bin/proxy-tunnel

run-tunnel: bin/proxy-tunnel
	bin/proxy-tunnel

bin/proxy-tunnel: bin/$(TUNNEL)-tunnel
	cp $< $@

.PHONY: go-rerouter/tunnel
go-tunnel/tunnel:
	$(MAKE) -C go-tunnel tunnel
bin/go-tunnel: go-tunnel/tunnel bin/
	cp $< $@

%/:
	mkdir -p $@

clean:
	rm -rf bin
	$(MAKE) -C go-rerouter clean
	$(MAKE) -C go-tunnel clean
	$(MAKE) -C tunnel clean