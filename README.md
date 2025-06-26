# Transparent proxying with eBPF and Go

⚠️ Don't actually use this! There are much better ways to do this; for example,
[tun2socks](https://github.com/xjasonlyu/tun2socks) provides a great proxying
tunnel, and its wiki has all you need to set it up to be transparent. There are
**MANY** "rerouters" you can use to route traffic to a tunnel, though the
simplest one is probably just using NFTables (you can find a basic example
[here](https://gist.github.com/Blokyk/00b8a9283f770db7113ddad64adbe519), but
there are much better ones around).

*This project was mainly a way for me to learn about eBPF, and that goal has
been fulfilled quite nicely for a first project. I don't particularly plan
on maintaining it any further (and honestly, seeing so many much better
alternatives has somewhat demotivated me). I'm not archiving it since I might
make a few more commits here and there in the future when I'm feeling in the
mood, but don't expect anything.*

## What ?

A "transparent" or "invisible" proxy is one that acts without the user needing
to configure it. It generally doesn't affect requests significantly but instead
just forwards them silently.

This repository includes an eBPF program that redirects all outgoing TCP
requests to a local server listening on a specific port (by default,
18000). That server is then able to connect to a proxy by itself, and
tunnel the packets through there.

**Right now, this doesn't support NTLM authentication, so for that
scenario you'll still have to use Cntlm first, and redirect the packets
there.** It also doesn't support remote proxies, but that shouldn't be too
hard to fix, since they're easier to support than local ones; I just
implemented the things I needed first. [See the open issues for details](https://github.com/Blokyk/transparent-proxy-ebpf/issues).

*I'm not a Go dev, this is a fork of [dorkamotorka/transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)
that I tweaked to my needs. Feel free to submit pull requests or issues
for any blunder I might have made!*

## Why ?

I'm a student that is currently forced to work on a school project
behind the school's (NTLM-authenticated) proxy, with no real way to
bypass it easily without getting in trouble. However, most toolchains,
runtimes, and programs have an absolutely abysmal support for proxies,
especially authenticated ones. It's also **wildly** unsafe to just
give out proxy logins to any program that needs internet access.

While the authentication problems can be somewhat relieved by using
[Cntlm](https://cntlm.sourceforge.net/), proxy support is still quite
lacking, especially for graphical or specialized programs. Some of them
don't read environment variables but instead rely on hidden options; others
have to be passed through an intermediate program; and others still just
don't support it at all. (Coincidentally, the Go toolchain has pretty
bad/weird support for proxies as well, so this was a *pleasure* to write.)

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

You can then build the app with a simple `make all`, install the binaries (into
`/usr/local` by default) with `sudo make install`.

```sh
make all && sudo make install
```

(Check `make help` for more details and compile-time options.)

You can then run `ebpf-rerouter` and `proxy-tunnel` just as any other program
(as long as the installation prefix is in your PATH of course). You should refer
to each command's help for more info.

> [!NOTE]
> For a more permanent and automatic solution for managing the
> rerouter and tunnel, see [the sample systemd files in `systemd/`](systemd/).

## Running && testing

Running the tunnel and rerouter is as easy as running these commands in two
different shells:
```sh
# in shell 1:
make run-tunnel

# in shell 2:
make run-rerouter
```

> [!NOTE]
> You will need elevated privilege to run the rerouter; you *are* inserting
> a packet rewriter into the kernel after all, and then tunneling your entire.

Currently, this is written mostly to pass things onto a local
unauthenticated proxy, like Cntlm. If you have that installed and setup properly,
you should configure it to listen on port 8080 (or modify
[`REAL_PROXY_PORT` in `app.go`](https://github.com/Blokyk/transparent-proxy-ebpf/blob/v0.1/main.go#L27)),
**and then** launch this transparent proxy. Now, even without configuring any
proxy for the different apps on your computer (browser, apt, pip, git, etc.),
everything should connect perfectly! :D
