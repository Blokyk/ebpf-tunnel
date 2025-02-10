# Transparent proxying with eBPF and Go

## What ?

A "transparent" or "invisible" proxy is one that acts with the user needing to
configure it. It generally doesn't affect requests significantly but instead
just forwards them silently.

This repository includes an eBPF program that redirects all outgoing TCP
requests to a local server listening on a specific port (by default,
18000). That server is then able to connect to a proxy by itself, and
tunnel the packets through there.

**Right now, this doesn't support NTLM authentication, so for that
scenario you'll still have to use Cntlm first, and redirect the packets
there.** It also doesn't support remote proxies, but that should be too
hard to fix, since they're easier to support than local ones; I just
implemented the things I needed first. [See the open issues for details](https://github.com/Blokyk/transparent-proxy-ebpf/issues)

*I'm not a Go dev, this is a fork of [dorkamotorka/transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)
that I tweaked to my needs. Feel free to submit pull requests or issues
for any blunder I might have made!*

## Why ?

I'm a student that is currently forced to work on a school project
behind the school's (authenticated, NTLM) proxy, with no real way to
bypass it easily without getting in trouble. However, most toolchains,
runtimes, and programs have an absolutely abysmal support for proxies,
especially authenticated ones. It's also **wildly** unsafe to just
give out proxy logins to any program that needs internet access.

While the authentication problems can be somewhat relieved by using
[Cntlm](https://cntlm.sourceforge.net/), proxy support is still quite
lacking, especially for graphical or specialized programs. Some of them
don't read environment variables instead need hidden options, others
have to be passed through an intermediate program, and others still just
don't support it at all. (Coincidentally, the Go toolchain has pretty
bad/weird support for proxies as well, this was a *pleasure* to modify.)

Ideally, we'd like *all* packets to go through the proxy automatically,
on a system-wide basis, without the program having to care about it at
all. With **eBPF**, this is actually possible! eBPF is a kernel subsystem
that allows us to capture, filter, and rewrite packets, which is ideal
for our use case.

## Building

To be able to use eBPF, you'll need `llvm`/`llvm-dev` and `clang`, the
Linux headers, and `libbpf`.

On Ubuntu, this will be:
```sh
sudo apt install llvm-dev clang linux-headers-generic libbpf-dev
```

You also need to install the headers for x86 platform, as needed by eBPF. This
can be done by either installing any of the following, as applicable to your
system:
- `libc6-dev-i386` *recommended* -- most lightweight, doesn't need any config
- `libc6-dev:i386` -- needs to enable i386 architecture for `dpkg`/`apt`
- `gcc-multilib` -- includes everything possibly needed and more, but doesn't
  need any `dpkg` architecture change

You can then generate the eBPF->Go bindings with
```sh
go generate
```

And then build the app with
```sh
go build
```

## Running && testing

<details>
    <summary>
        Demo of <a href="https://github.com/dorkamotorka/transparent-proxy-ebpf">original app from dorkamotorka</a>
    </summary>
    <video src="https://github.com/user-attachments/assets/325745b2-9be1-43cd-bd64-14fa6ac5f5e0">
</details>

You need elevated privilege to run this (you're inserting a packet
rewriter into the kernel after all):
```
sudo ./ebpf-tunnel
```

Currently, this is written mostly to pass things onto a local
unauthenticated proxy, like Cntlm. If you have that setup and installed,
you should configure it to listen on port 8080 (or modify
[`REAL_PROXY_PORT` in `main.go`](https://github.com/Blokyk/transparent-proxy-ebpf/blob/8208e2727114ee22ac5813741fbaec760e4917cd/main.go#L27)), **and then** launch this transparent proxy. Now, even without
configuring any proxy for the different apps on your computer (browser,
apt, pip, git, etc.), everything should connect perfectly!