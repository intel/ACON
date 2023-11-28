# Attested Container (ACON) Command Line Application

## Development Environment Setup

To build and run `aconcli`, you need Golang, protocol buffer, and Go plugins for protocol compiler.

- For Golang, please refer to the installation document [here](https://go.dev/doc/install). Version 1.20.6 and higher is recommended.

- For protocol buffer and Go plugins, please refer to the installation guide listed [here](https://grpc.io/docs/languages/go/quickstart/).

## Build, install and clean the aconcli project

To build `aconcli` project, change to the project's top level directory:

```sh
go generate && go build # `-ldflags "-s -w"` can optionally be appended to strip symbols
```

To clean up:

```sh
go clean
```

## Running the aconcli tool

To see available commands run:

```
aconcli -h
```

The general format of `aconcli` commands is:

```
aconcli [global_flags]... command [flags]...
```

Shell completion is supported. For example, to add completion to the current `bash`:

```sh
. <(aconcli completion bash)
```


## About the sample ACON-VM start sript

With `aconcli`, a [default ACON-VM start script](acon-startvm) is provided to launch *ACON VM*s (*aVM* for short hereon). Environment variables are used by `aconcli run` (and potentially users as well) to convey parameters to customize the script's behavior. Users can supply their own start scripts but they must adhere to the semantics of the environment variables listed in the table below.

|ENV VAR|Description
|-|-
|`ATD`|Set (to any non-nil string) to launch TD; unset to launch VM. `td-$ATD` will be used as the host name of the *aTD*.
|`ATD_QEMU`|Executable name (or path) of *QEMU*, default `qemu-kvm`.
|`ATD_CID`|VSOCK CID of the *aTD*.<ul><li>Unset (default) - disable VSOCK support. <li>`$ATD_CID <= 2` - *PID* will be used as CID. <li>Otherwise - `$ATD_CID` will be used as CID as is.
|`ATD_MEMSZ`|*aTD* memory size, default `1g` (1GB).
|`ATD_NVP`|Number of virtual processors, default `1`.
|`ATD_TCPFWD`|TCP forwarding rules - a comma (`,`) separated list of rules in the form of `[host_port:]guest_port`. For example,<ul><li>`ATD_TCPFWD=1025` - Forward guest port `1025` to the same port (`1025`) on the host. <li>`ATD_TCPFWD=5022:22,1025` - Forward guest port `22` to host port `5022` and guest port `1025` to host port `1025`.</ul> `aconcli run` **appends** to `$ATD_TCPFWD` to forward `acond` port to the host. Users can set up forwarding rules for containers by setting this variable prior to invoking `aconcli`.
|`ATD_BIOS`|Path to the virtual BIOS image, default `/usr/share/qemu/OVMF.fd`.
|`ATD_RD`|Path to the initrd image, default `initrd.img` in the same directory as where the script resides.
|`ATD_KERNEL`|Path to the guest kernel, default `vmlinuz` in the same directory as where the script resides.
|`ATD_KPARAMS`|Additional kernel command line. `aconcli run` **appends** to `$ATD_KPARAMS` to pass parameters to `acond`.