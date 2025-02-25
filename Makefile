TUNNEL ?= go
REROUTER ?= go
PREFIX ?= /usr/local

.PHONY: all rerouter tunnel install
all: rerouter tunnel

$(PREFIX)/bin/%: bin/%
	install -Dt $(PREFIX)/bin $<

install: $(PREFIX)/bin/ebpf-rerouter $(PREFIX)/bin/proxy-tunnel

install-sd:
	$(MAKE) -C systemd install

help:
	@echo 'Generic targets:'
	@echo '  - all           Builds the default variants of the rerouter and the tunnel'
	@echo '  - clean         Delete generate files and binaries'
	@echo
	@echo 'Installation:'
	@echo '  - install       Installs the rerouter and tunnel to the configured'
	@echo '                  prefix. Might require sudo.'
	@echo '  - install-sd    Installs a set of sample systemd service files. See'
	@echo '                  systemd/README for more info. Requires sudo.'
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