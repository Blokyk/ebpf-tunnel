package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

func setPidForPort(port uint16, boundPidsMap *ebpf.Map) error {
	pid, err := getPidFromPort(port)
	if err != nil {
		return err
	}

	// if we found the PID listening on this port, update the the `bound_pid` map,
	// since that means the proxy already called bind() so it won't be caught by our eBPF
	log.Printf("Process for port %d has PID %d, will ignore any connection from it", port, pid)

	err = boundPidsMap.Update(&pid, &port, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update boundPids map: %w", err)
	}

	return nil
}

func addPortToBypass(port uint16, configMap *ebpf.Map, whitelist *ebpf.Map) error {
	var key uint32 = 0
	var config rerouterConfig

	err := configMap.Lookup(&key, &config)
	if err != nil {
		return err
	}

	if config.WhitelistCount >= uint16(whitelist.MaxEntries()) {
		return fmt.Errorf("reached maximum whitelist capacity (%d), can't add any more", uint16(whitelist.MaxEntries()))
	}

	nextIdx := uint32(config.WhitelistCount)
	err = whitelist.Update(&nextIdx, &port, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	config.WhitelistCount++

	err = configMap.Update(&key, &config, ebpf.UpdateExist)
	if err != nil {
		return err
	}

	return nil
}

func bypassPort(port uint16, maps rerouterMaps) error {
	err := addPortToBypass(port, maps.MapConfig, maps.MapBypassPorts)
	if err != nil {
		return err
	}

	err = setPidForPort(port, maps.MapBypassPids)
	if err != nil {
		return fmt.Errorf("tried to whitelist port '%d' but: %w. We'll catch the PID with bind() hook", port, err)
	}

	return nil
}
