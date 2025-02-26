package main

//go:generate sh -c "rm -f *_bpfel.go *_bpfeb.go"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type Config rerouter rerouter.ebpf.c -- -g -I/usr/include/i386-linux-gnu -I/usr/i686-linux-gnu/include

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	CGROUP_PATH     = "/sys/fs/cgroup" // Root cgroup path
	TUNNEL_PORT     = 18000            // Port where the tunnel (in go or c) listens
	REAL_PROXY_PORT = 8080             // Port where the real proxy (cntlm) listens
	BPF_FS          = "/sys/fs/bpf/rerouter"
)

type rerouterLinks struct {
	Connect4Link  link.Link
	SockOpsLink   link.Link
	SockOptLink   link.Link
	PostBind4Link link.Link
	CloneProbe    link.Link
	Clone3Probe   link.Link
}

func (links *rerouterLinks) Close() {
	links.Connect4Link.Close()
	links.SockOpsLink.Close()
	links.SockOptLink.Close()
	links.PostBind4Link.Close()
	links.CloneProbe.Close()
	links.Clone3Probe.Close()
}

func (links *rerouterLinks) Iterate() map[string]link.Link {
	return map[string]link.Link{
		"Connect4Link":  links.Connect4Link,
		"SockOpsLink":   links.SockOpsLink,
		"SockOptLink":   links.SockOptLink,
		"PostBind4Link": links.PostBind4Link,
		"CloneProbe":    links.CloneProbe,
		"Clone3Probe":   links.Clone3Probe,
	}
}

func makeBpfPinFolder() error {
	// make sure the /sys/fs/bpf/rerouter folder exists so we can our objects there
	err := os.Mkdir(BPF_FS, 0755)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("failed to create rerouter bpf pin directory: %w", err)
	}

	return nil
}

// Attach eBPF programs to the root cgroup and the right kprobes
func attachProgs(objs rerouterObjects) (rerouterLinks, error) {
	cgroup := CGROUP_PATH

	connect4Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgConnect4,
	})
	if err != nil {
		return rerouterLinks{}, fmt.Errorf("(CgPostBind4 program) %w", err)
	}

	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.CgSockOps,
	})
	if err != nil {
		return rerouterLinks{}, fmt.Errorf("(CgPostBind4 program) %w", err)
	}

	sockoptLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup,
		Attach:  ebpf.AttachCGroupGetsockopt,
		Program: objs.CgSockOpt,
	})
	if err != nil {
		return rerouterLinks{}, fmt.Errorf("(CgPostBind4 program) %w", err)
	}

	postBind4Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup,
		Attach:  ebpf.AttachCGroupInet4PostBind,
		Program: objs.CgPostBind4,
	})
	if err != nil {
		return rerouterLinks{}, fmt.Errorf("(CgPostBind4 program) %w", err)
	}

	cloneProbeLink, err := link.Kretprobe("sys_clone", objs.ProbeClone, nil)
	if err != nil {
		return rerouterLinks{}, fmt.Errorf("(clone probe) %w", err)
	}

	clone3ProbeLink, err := link.Kretprobe("sys_clone3", objs.ProbeClone3, nil)
	if err != nil {
		return rerouterLinks{}, fmt.Errorf("(clone3 probe) %w", err)
	}

	return rerouterLinks{
		connect4Link,
		sockopsLink,
		sockoptLink,
		postBind4Link,
		cloneProbeLink,
		clone3ProbeLink,
	}, nil
}

func getPinPath(objName string) string { return filepath.Join(BPF_FS, objName) }

func pinProg(prog *ebpf.Program, progName string) error {
	pinPath := getPinPath(progName)

	err := prog.Pin(pinPath)
	if err != nil {
		return fmt.Errorf("failed to pin program '%s': %w", progName, err)
	}

	return nil
}

func loadPinned(progName string) (*ebpf.Program, error) {
	pinPath := getPinPath(progName)
	pinnedProg, err := ebpf.LoadPinnedProgram(pinPath, &ebpf.LoadPinOptions{})

	if err != nil {
		return nil, fmt.Errorf("couldn't load already-pinned program '%s': %w", progName, err)
	}

	return pinnedProg, nil
}

func loadAndPinProgs(col *ebpf.Collection, _ *ebpf.CollectionSpec) error {
	for progName, prog := range col.Programs {
		err := pinProg(prog, progName)

		// program is already pinned
		if errors.Is(err, syscall.EEXIST) {
			prog, err = loadPinned(progName)
			if err != nil {
				return fmt.Errorf("failed to load '%s' from pin: %w", progName, err)
			}
			col.Programs[progName] = prog
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func pinLink(link link.Link, linkName string) error {
	pinPath := getPinPath(linkName)

	err := link.Pin(pinPath)
	if err != nil {
		return fmt.Errorf("failed to pin link '%s': %w", linkName, err)
	}

	return nil
}

func pinAllLinks(links *rerouterLinks) error {
	for linkName, link := range links.Iterate() {
		err := pinLink(link, linkName)

		if err != nil && !errors.Is(err, ebpf.ErrNotSupported) && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}

	return nil
}

func unpinAll() error {
	dirEntries, err := os.ReadDir(BPF_FS)
	if err != nil {
		return nil
	}

	for _, f := range dirEntries {
		path := filepath.Join(BPF_FS, f.Name())
		prog, err := ebpf.LoadPinnedProgram(path, nil)
		if err != nil {
			return err
		}

		err = prog.Unpin()
		if err != nil {
			return nil
		}
	}

	return nil
}
