SD_PREFIX ?= /usr/local/lib/systemd/system

.PHONY: help install install-rerouter install-tunnel

help:
	@echo 'Available targets:'
	@echo '  - install-rerouter  Installs a systemd service file to run the rerouter'
	@echo '                      at startup, and a proxy-tunnel target to synchronise'
	@echo '                      the rerouter with an associated tunnel'
	@echo
	@echo '  - install-tunnel    Installs a sample systemd service file to use the'
	@echo '                      tunnel with Cntlm, which fulfills proxy-tunnel.target'
	@echo
	@echo '  - install           install-rerouter + install-tunnel'
	@echo '  - uninstall         Stops the rerouter and tunnel services, and removes'
	@echo '                      their unit files'
	@echo
	@echo 'By default, the unit files will be installed to `/usr/local/lib/systemd/system`.'
	@echo 'The SD_PREFIX variable can be used to change this path.'
	@echo
	@echo "More information is available in this directory's README.md"


install: install-rerouter install-tunnel

$(SD_PREFIX)/%: %
	install -Dt $(SD_PREFIX) $<

# we can't use a dependency on $(SD_PREFIX)/% because we don't
# actually know if we want to install this unit or not
#
# only install sys-fs-bpf.mount if /sys/fs/bpf doesn't exist
ensure-bpf-mount:
	@[ -d "/sys/fs/bpf" ] || $(MAKE) install-bpf-mount

install-bpf-mount: $(SD_PREFIX)/sys-fs-bpf.mount
	systemctl enable $<

install-rerouter: | ensure-bpf-mount
install-rerouter: $(SD_PREFIX)/ebpf-rerouter.service $(SD_PREFIX)/proxy-tunnel.target
	systemctl enable $^

install-tunnel: | install-rerouter
install-tunnel: $(SD_PREFIX)/cntlm-tunnel.service $(SD_PREFIX)/proxy-tunnel.target
	systemctl enable $^

uninstall-rerouter:
	systemctl stop ebpf-rerouter.service
	systemctl disable ebpf-rerouter.service
	rm $(SD_PREFIX)/ebpf-rerouter.service
	rm $(SD_PREFIX)/proxy-tunnel.target

uninstall-tunnel:
	systemctl stop cntlm-tunnel.service
	systemctl disable cntlm-tunnel.service
	rm $(SD_PREFIX)/cntlm-tunnel.service

uninstall: uninstall-rerouter uninstall-tunnel