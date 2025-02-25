# Automatically setting up the rerouter and tunnel with systemd

`ebpf-rerouter` has two main modes of operation: long-running eBPF manager (with
the `run` command), or short-term runner/stopper (with `start`/`stop`). While
you could just let it run in a background terminal for your entire session,
you can also integrate this with a service manager like `systemd`, to easily
manage this whole thing.

While this isn't a particularly complex thing to setup, there are times where
you're ok with writing systemd unit files, and then there's real life, where
you really wish someone already did. This folder is that!

There are two pretty generic files, which should be re-usable for almost
anything you want to do with this project:
  - [**`ebpf-rerouter.service`**](./ebpf-rerouter.service) -- allows starting,
  stopping, and reloading the eBPF manager. By default, it will participate to
  `multi-user.target`, meaning that it will be started before login for
  non-rescue shells; it also fails/shuts down in sync with the `proxy-tunnel.target`,
  so that it doesn't try to reroute to a non-existant tunnel (in case it fails
  or gets turned off)
  - [**`proxy-tunnel.target`**](./proxy-tunnel.target) -- a generic target that
  can be fulfilled by any service that provides a tunnel to a proxy

These units can be installed with `sudo make install-rerouter`.

Also included is [`cntlm-tunnel.service`](./cntlm-tunnel.service), a basic
service to fulfill the `proxy-tunnel.target` with the `proxy-tunnel` tunnel
provided by this project. The service stops the tunnel in case Cntlm fails or
shuts down, which will also disable the rerouter, preventing packets from
being rerouted/tunnel into nothingness.

It can be installed with `sudo make install-tunnel`.

Once you've installed the tunnel, you can start the rerouter just like any other
service, with `sudo systemctl start ebpf-rerouter`. The tunnel and Cntlm will
also automatically get started with the rerouter.

For shutting down, the tunnel and Cntlm won't get shutdown with `ebpf-rerouter`
automatically -- you'll need to shut them down independently. Alternatively, you
can stop either of them instead, which will deactivate the rerouter as well.

> [!NOTE]: A [`sys-fs-bpf.service`](./sys-fs-bpf.mount) file is also available;
> it automatically mounts the `bpffs` filesystem, which is required for the
> rerouter to run without a managing process. On recent systems, this unit
> should be useless, or it might already exist -- the makefile checks whether
> or not it is needed before installing it