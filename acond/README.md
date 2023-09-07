# ACON Daemon

## Introduction

The ACON Daemon is responsible for:

- Act as init for the TD guest Linux kernel.
- Manage ACON images (referred to as *Image*s hereon).
- Manage ACON containers (running instances of *Image*s, referred to as *Container*s hereon).
- Facilitate inter-*Container* communication.
- Measurement of and attestation to loaded *Image*s and/or runtime events.
- Multiplexing Linux console among *Container*s.

The ACON Daemon executable has the file name `acond`, hence is referred to as `acond` hereon.

## Building ACON Daemon

`acond` can be built on [Rust 2018](https://doc.rust-lang.org/edition-guide/rust-2018/index.html) or later, and supports [`x86_64-unknown-linux-gnu`](#glibc-based-builds) and [`x86_64-unknown-linux-musl`](#musl-libc-based-builds) targets.

`acond` can be built as either a static standalone or a dynamically linked executable.

### Building `acond` in `rust` Container

It's recommended to use the [`rust`][rust-docker] docker container image to build `acond` because it's easy to setup and also necessary to reproduce the `acond` binary.

#### Prerequisites

- [Bash](https://www.gnu.org/software/bash/) version 5 or higher - This is a standard component  in most Linux distros today.
- [Docker Desktop](https://docs.docker.com/desktop/) - See [Install Docker Desktop on Linux](https://docs.docker.com/desktop/install/linux-install/) for detailed instructions.

#### musl-libc Based Builds

[musl-libc][musl-libc] is known for its small size. The container image `rust:alpine` is ideal for building [musl-libc](https://musl.libc.org) based executables.

[`acon-build.env`](../scripts/acon-build.env) provides a collection of the bash functions to assist in building `acond` and initrd images. `start_rust_buildenv` is one of those shell functions and can be used to create an [Alpine][alpine-linux] based [`rust`][rust-docker] container, like below.

```sh
cd /path/to/ACON_PROJECT_ROOT
. scripts/acon-build.env
# NOTE: The optional U=. causes the container to setuidgid to current user's UID/GID
U=. start_rust_buildenv
```

A command prompt (of the newly created `rust` docker container) will then come up and resemble the following.

```
ACON Repo       /path/to/ACON
Rust OCI Image  rust:alpine
INFO	acon-rust.USERNAME.0123456789ab: Creating new container...
INFO	Installing downloaded packages in /acon/scripts/deps/rust-1.72.0/alpine ...
INFO	To refresh dependent packages, simply delete '/acon/scripts/deps/rust-1.72.0/alpine/PACKAGES-INFO'
fetch https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/APKINDEX.tar.gz
fetch https://dl-cdn.alpinelinux.org/alpine/v3.18/community/x86_64/APKINDEX.tar.gz
(1/11) Installing daemontools-encore (1.11-r1)
(2/11) Installing libprotobuf (3.21.12-r2)
(3/11) Installing libprotobuf-lite (3.21.12-r2)
(4/11) Installing libprotoc (3.21.12-r2)
(5/11) Installing musl-dev (1.2.4-r1)
(6/11) Installing pkgconf (1.9.5-r0)
(7/11) Installing openssl-dev (3.1.2-r0)
(8/11) Installing openssl-libs-static (3.1.2-r0)
(9/11) Installing zlib-dev (1.2.13-r1)
(10/11) Installing protoc (3.21.12-r2)
(11/11) Installing protobuf-dev (3.21.12-r2)
Executing busybox-1.36.1-r2.trigger
OK: 201 MiB in 38 packages
/acon/acond $
```

Please note `start_rust_buildenv` identifies (using `git rev-parse --show-toplevel`) and maps `path/to/ACON_PROJECT_ROOT` to `/acon` inside the container, and sets the working directory to `/acon/acond` automatically. Therefore, building `acond` will be as simple as below.

```sh
./build
```

By default `./build` builds a dynamically linked executable. To link libraries to `acond` statically, use `./build_static` instead.

It's worth noting that both `./build` and `./build_static` pass through their command line arguments to `cargo build`. For example, the command below builds a dynamically linked `acond` in release mode with the feature `full` enabled (which enables all available features of `acond`).

```sh
./build -r -Ffull
```

#### glibc Based Builds

`start_rust_buildenv` supports [Alpine][alpine-linux] Linux only, so building a [glibc][gnu-libc] based `acond` must be done manually as of this writing.

**Note**: [`rust`][rust-docker] supports [Debian][debian-linux] and [Ubuntu][ubuntu-linux] as two options for its [glibc][gnu-libc] toolchains. `rust:slim` is used here for demonstration purpose and can be substituded by any variant of Debian or Ubuntu. See [here][rust-docker-tags] for a complete list of tags.

1. Build a container image from `rust:slim` (which is based on Debian *bookworm* as of this writing) with dependencies installed.

   ```sh
   docker build -t acon-rust:slim -f - . << END
   FROM rust:slim
   RUN apt update && apt install -y pkg-config libssl-dev protobuf-compiler daemontools
   END
   ```

2. Create a container from the image above.

   ```sh
   docker run -it -v /path/to/ACON_PROJECT_ROOT:/acon -w /acon/acond acon-rust:slim
   ```

3. Build `acond` inside the container, by typing into the container's command prompt

   ```sh
   ./build
   ```

   Or to build in release mode with all `acond` features enabled, type

   ```sh
   ./build_static -r -Ffull
   ```

#### Reproducing Build Environment

`start_rust_buildenv` keeps in `/path/to/ACON_PROJECT_ROOT/scripts/dep/rust-VERSION/OS/` copies of all packages (e.g., *.apk files for Alpine Linux) installed in the container, along with a `PACKAGES-INFO` file recording the OS version and date/time when those packages were downloaded. Those files, along with a proper [`rust`][rust-docker] tag, can be used to reproduce the build environment.

For example, given `scripts/deps/rust-1.72.0/alpine/PACKAGES-INFO` and the `*.apk` files, the commands below reproduce the build environment.

```sh
cd /path/to/ACON_PROJECT_ROOT
. scripts/acon-build.env
. scripts/deps/rust-1.72.0/alpine/PACKAGES-INFO
RUSTAG=1.72.0-alpine${VERSION%.*} start_rust_buildenv
```

### Building `acond` in Host Environment

#### Installing Prerequisites

- [Install Rust](https://www.rust-lang.org/tools/install) - The command below works for most Linux distros.

  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- Install dependent libraries/tools - Different distros may use different package managers or package names.
  <details><summary>Alpine</summary>

  ```sh
  apk add musl-dev openssl-dev protobuf-dev openssl-libs-static
  ```
  </details>
  <details><summary>Debian/Ubuntu</summary>

  ```sh
  apt install -y pkg-config libssl-dev protobuf-compiler
  ```
  </details>

#### Building `acond` using `cargo`

- To build `acond` with the default toolchain and target in release mode with all `acond` features enabled.

  ```sh
  cd /path/to/ACON_PROJECT_ROOT/acond

  # NOTE: acond may be statically or dynamically linked depending on the installed rust toolchain and target
  cargo build -r -Ffull
  ```

- To build a statically linked `acond` in release mode with default features.

  ```sh
  cd /path/to/ACON_PROJECT_ROOT/acond

  # NOTE: target-feature=+crt-static is necessary on GNU distros only
  CARGO_BUILD_RUSTFLAGS=-Ctarget-feature=+crt-static cargo build -r
  ```

- To build a dynamically linked `acond` in release mode with all `acond` features enabled.

  ```sh
  cd /path/to/ACON_PROJECT_ROOT/acond
  # NOTE: target-feature=-crt-static is necessary on MUSL distros only
  CARGO_BUILD_RUSTFLAGS=-Ctarget-feature=-crt-static cargo build -r -Ffull
  ```

## Building initrd Image

TBD

[rust-docker]: https://hub.docker.com/_/rust/
[rust-docker-tags]: https://hub.docker.com/_/rust/tags
[musl-libc]:https://musl.libc.org
[gnu-libc]:https://www.gnu.org/software/libc/
[alpine-linux]:https://www.alpinelinux.org
[debian-linux]:https://www.debian.org
[ubuntu-linux]:https://www.ubuntu.com
