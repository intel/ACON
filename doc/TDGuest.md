# TDX-enabled Linux Kernel and QEMU

This guide provides instructions for building TDX-enabled Linux guest kernel and initrd (Initial RAM Disk) for booting a TDX VM using *QEMU*.

## Quick Start

This chapter contains simple steps for building the Linux kernel and the initrd image using the default/recommended settings.

**Note**: Audience is assumed familiar with the boot flow of TDs and [Direct Linux Boot][qemu-doc-linuxboot]. [TD Measured Boot](#td-measured-boot) provides a brief introduction to those topics.

### Building Linux Kernel

Firstly, the kernel source code must be downloaded. TDX support is being upstreamed at the time this guide is written, and the latest TDX guest code can be accessed at https://github.com/intel/tdx/tree/guest-next. The command below clones the repo.

```sh
git clone https://github.com/intel/tdx -b guest-next
```

Then, configure the kernel. It's recommended to create a build directory separated from the kernel source directory. A sample kernel configuration file ([`config-acon`][file-config-acon]) is provided and can be used to configure a kernel using the commands below.

```sh
mkdir -p /path/to/build_dir
cd /path/to/build_dir

cp /path/to/acon_source/doc/config-acon .config

make -C /path/to/kernel_source O=$PWD olddefconfig
```

**Note:** [`config-acon`][file-config-acon] is a symbolic link pointing to the real kernel configuration file whose name contains at the end the first 12 digits of the git commit ID of the source tree - e.g, given the configuration file named `config-6.4.0-rc1-acon-00117-ga324aa0d829e`, the source tree for which it configured originally can be viewed at https://github.com/intel/tdx/tree/a324aa0d829e, and can be checked out locally using the command below.

```sh
git checkout a324aa0d829e
```

Finally, build the kernel.

```sh
make -j$(getconf _NPROCESSORS_ONLN)
```

After a successful build, the kernel binary will be `/path/to/build_dir/arch/x86/boot/bzImage`, and can be installed (i.e., copied then renamed to `vmlinuz-VERSION...`) into a user-specified directory by the command below.

```sh
make INSTALL_PATH=/path/to/target/dir install
```

### Creating initrd (Initial RAM Disk) Image

[initrd][initrd] is a *CPIO* archive that contains a directory tree to be mounted at `/` when the kernel boots, and must contain the executable file `/init` to be launched by the kernel as the first user mode process.

Building an initrd image is cumbersome, therefore a few shell functions are provided in [`initrd-helper-funcs.sh`](../scripts/initrd-helper-funcs.sh) to assist users in creating/customizing initrd images. Details of those shell functions are provided [later](#customizing-initial-ram-disk) in this guide.

To include those functions in the current shell (only `sh`/`bash` are supported for now) environment, simply source the script like below.

```sh
source /path/to/acon_source/scripts/initrd-helper-funcs.sh
```

The rest of this section demonstrates the steps for building/customizing initrd images with two examples based on [`busybox`](#busybox-based-initrd) and [`alpine`](#alpine-based-initrd), respectively.

#### `busybox` Based initrd

[busybox](https://busybox.net/) provides a minimal shell environment and is widely used in initrd images of various Linux distros.

Here are the steps to create an initrd from the [`busybox` docker container image](https://hub.docker.com/_/busybox).

1. Download the latest `busybox` docker image (assuming `docker` has been installed properly).

   ```sh
   docker pull busybox:uclibc
   ```

2. Source the help script mentioned above.

   ```sh
   source /path/to/acon_source/scripts/initrd-helper-funcs.sh
   ```

3. Invoke `get_initrd` to create the initrd image - The command below will create a new directory named `bbox/` along with a *CPIO* archive named `initrd-bbox.cpio`, in the current directory. `initrd-bbox.cpio` is the initrd image.

   ```sh
   gen_initrd bbox busybox:uclibc
   ```

4. The directory `bbox/` facilitates customization. For example, to add a *virtio-blk* (e.g., `/dev/vda`) as a `swap` device, we can

   1. Append an entry to `bbox/etc/fstab`

      ```sh
      chmod +w bbox/etc/fstab
      echo "/dev/vda none swap sw,discard 0 0" >> bbox/etc/fstab
      ```

   2. Repack the initrd image

      ```sh
      create_initrd bbox
      ```

   3. *QEMU* will need a disk image file for emulating `/dev/vda`. The commands below create a disk image of 256 MB in size and format it to be a `swap` device.

      ```sh
      # Create a file of 256MB in size
      dd if=/dev/zero of=256m.raw bs=1M count=1 seek=255

      # Format it as a swap device image
      mkswap 256m.raw
      ```

5. Optionally, initrd images can be compressed. For exmaple,

   ```sh
   xz_initrd initrd-bbox.cpio
   ```

   The above command will reduce the size of `initrd-bbox.cpio` from 1.3MB to around 640KB (and append `.xz` to the image file name).

   **Note:** Compression can also be done when generating (`gen_initrd`) or repacking (`create_initrd`) the initrd image, simply by setting the environment variable `C` to the suffix of the compressed archive (E.g., `C=xz gen_initrd bbox busybox:uclibc` generates `initrd-bbox.cpio.xz`).

6. Finally, we can launch a VM using the initrd image and the kernel built previously. Please note the script [`start-qemu.sh`](../scripts/start-qemu.sh) used below wraps a complex *QEMU* command line that is explained in details in [QEMU Command Line for Launching TD][qemu-cmdline].

   ```sh
   RD=initrd-bbox.cpio.xz DRV=256m.raw /path/to/acon_source/scripts/start-qemu.sh /path/to/vmlinuz-6.4.0-rc1-acon-00117-ga324aa0d829e
   ```

   If everything works out smoothly, a Linux command prompt will be brought up and the command below in the guest's terminal will show 256MB of total swap space.
   ```sh
   free -h
   ```

   **Note**: On a TDX-enabled platform, a TD (instead of a regular VM) can be launched by setting the environment variable `TD` to any non-empty string, like below.

   ```sh
   TD=1 RD=initrd-bbox.cpio.xz DRV=256m.raw /path/to/acon_source/scripts/start-qemu.sh /path/to/vmlinuz-6.4.0-rc1-acon-00117-ga324aa0d829e
   ```

#### `alpine` Based initrd

[alpine](https://www.alpinelinux.org/) is a lightweight Linux distro based on `busybox` and [musl](https://www.musl-libc.org/) libc.

Comparing to [`busybox` initrd](#busybox-based-initrd), `alpine` is bigger but also offers much more features through its [Alpine Package Keeper](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper). The example in this section adds the following features to initrd.

- `device-mapper` - For disk encryption.
- `e2fsprogs` - For creating `ext4` filesystem on block (*virtio-blk*) devices as temporary storage.
- `openssh-server` - SSH server.

Follow the steps below to create an initrd from the [`alpine` docker container image](https://hub.docker.com/_/alpine).

1. Download `alpine` container image and install required packages. Please note the resulted container will be tagged `a-initrd`.

   ```sh
   docker build -t a-initrd -f - . << END
   FROM alpine:latest
   RUN apk add device-mapper e2fsprogs openssh-server
   END
   ```

   **Note:** If behind a HTTP proxy, insert `https_proxy=PROXY_URL` between `RUN` and `apk` in the command snippet above.

2. Generate the initrd image - Here we name the directory `alpine/` hence the initrd image file name `initrd-alpine.cpio`. Setting the environment variable `F=1` overwrites various existing configuration files (e.g., `/etc/fstab`) in the `a-initrd` container directory tree.

   ```sh
   F=1 gen_initrd alpine a-initrd
   ```

3. Configure disk encryption - The generated `/etc/fstab` by default encrypts the first *virtio-blk* device (i.e., `/dev/vda`) and uses it as `swap`. Comments inside `/etc/fstab` contains detailed information regarding how to configure disk encryption. Below showcases how to configure disk encryption for the second *virtio-blk* device (i.e., `/dev/vdb`) and mount it to the directory `/ext4` - all by just appending a line to `/etc/fstab`.

   ```sh
   chmod +w alpine/etc/fstab
   echo "/dev/mapper/vdb@+ae /ext4 ext4 defaults 0 0" >> alpine/etc/fstab
   ```

   **Note:** `/init` sets up disk encryption using random keys (by reading keys from `/dev/urandom`) and reformat the device on every boot. That is, all data will be lost across boots.

   **Note:** The encryption algorithm is configured by the suffix (starting from `@`) of the device name. `@+ae` selects the default *Authenticated Encryption* scheme with random *IV* (currently `capi:authenc(cmac(aes),xts(aes))-random` in [Linux Crypto API][linux-crypto] notation).

4. Configure SSH server - `/init` generates random host keys on every boot. User keys however must be placed into initrd manually. The commands below generates a random 521-bit ECDSA key pair and copies the public key into the initrd directory as an authorized key for the `root` user.

   ```sh
   ssh-keygen -t ecdsa -b 521 -f id-test -N ''
   mkdir -p alpine/root/.ssh
   cp id-test.pub alpine/root/.ssh/authorized_keys
   ```

5. Repack and compress initrd.

   ```sh
   C=xz create_initrd alpine
   ```

6. [Launch VM](#launching-td) - We need two disk images (for emulating `/dev/vda` and `/dev/vdb`) and also need to setup TCP port forwarding for SSH sessions. Below we create two disk images in RAW format, of size 265MB and 64MB respectively, and forward the host TCP port `22222` to the guest TCP port `22`.

   ```sh
   # Create 2 disk images of size 256MB and 64MB, respectively
   dd if=/dev/zero of=256m.raw bs=1M count=1 seek=255
   dd if=/dev/zero of=64m.raw bs=1M count=1 seek=63

   # Start the VM with virtio-blk devices and port forwarding
   DRV=256m.raw,64m.raw TCPFWD=22222:22 RD=initrd-alpine.cpio.xz /path/to/acon_source/scripts/start-qemu.sh /path/to/vmlinuz-6.4.0-rc1-acon-00117-ga324aa0d829e
   ```

   **Note:** Again, a regular VM will be started by default, unless the environment variable `TD` is set to a non-empty string.

   If everything works out smoothly, a Linux console would be brought up.

   - `free -h` would show `swap` space of 256MB in size.
   - `mount -text4` would show `/dev/mapper/vdb@+ae` mounted at `/ext4`.
   - An SSH session could be started (from a different terminal on the same host) by the command below.

     ```sh
     ssh -i id-test -p 22222 root@localhost
     ```

### Launching TD

[`start-qemu.sh`](../scripts/start-qemu.sh) is an example shell script to showcase how to customize various aspects of a TD (or regular VM) suitable for hosting *ACON Container*s. It is capable of launching both regular VMs and TDs and has the following syntax.

```sh
[ENV_OVERRIDES]... start-qemu.sh [VMLINUZ] [QEMU_OPTIONS]...
```

Where,

- `ENV_OVERRIDES` are environment variable assignments that affect the script's behavior. Supported environment variables are detailed [later][qemu-cmdline] in this guide. The most notable one is `TD`, which if defined, instructs `start-qemu.sh` to start a TD. By default, a regular VM is started. The complete list of environment variables are given below.
- `VMLINUZ` is the kernel file path and default to `$(dirname $0)/vmlinuz` (i.e., `vmlinuz` in the same directory as the script itself) if omitted. Refer to [Building Linux Kernel](#building-linux-kernel) for instructions on building/customizing a kernel.
- Besides the kernel, an initrd image named `initrd` must also exist in the same directory as the script (unless overridden by `RD` environment variable). Refer to [Creating initrd (Initial RAM Disk) Image](#creating-initrd-initial-ram-disk-image) for more information.
- Additional *QEMU* options can be passed following `VMLINUZ`.

E.g., The command below starts a TD using kernel `vmlinuz` with the initrd image `initrd` in the current directory.

```
TD=guest ./start-qemu.sh
```

The table below lists all environment variables that alters `start-qemu.sh`'s behavior.

|Environment Variable|Description
|-|-
|`TD`|If set to a non-empty string, `start-qemu.sh` starts a TD, otherwise a regular VM is started. The host name will be set to `td-$TD` for a TD, or `vm` for a regular VM.
|`VP`|The number of vCPUs. If not set, *QEMU*'s default will be used.
|`M`|Memory size, default to `2g` (2GB).
|`CID`|The *CID* for the guest. <ul><li>If not set, *VSOCK* will be disabled for the guest. <li>If `$CID <= 2`, the guest *CID* will be set to the *QEMU* process's *PID*. <li>Otherwise, the guest *CID* will be set to `$CID`.
|`BIOS`|Path of the BIOS image, default to `/usr/share/qemu/OVMF.fd`.
|`RD`|Path of the initrd image, default to `$(dirname $0)/initrd`.
|`KA`|Additional kernel parameters.
|`TCPFWD`|A comma-separated list of port mappings, each of which could be either <ul><li>`HOSTPORT:GUESTPORT` - *QEMU* will forward *TCP* traffics towards `HOSTPORT` on the host to `GUESTPORT` on the guest.<li>`PORT` - *QEMU* will forward *TCP* traffics towards `PORT` on the host to the same `PORT` on the guest.</ul>
|`DRV`|A comma-separated list of disk image files to be passed to the guest as *virtio-blk* devices - i.e., the 1st image is mapped to `/dev/vda`, the 2nd to `/dev/vdb`, and so on. The image files' suffices determine their types, and must be either `.raw` or `.qcow2`.

Please refer to [QEMU Command Line for Launching TD](#qemu-command-line-for-launching-td) for detailed explanations of the *QEMU* command line options used internally by `start-qemu.sh`.

## TD Measured Boot

This chapter provides background information on how a TD boots and what are measured during boot. [Intel® TDX Virtual Firmware Design Guide][tdvf-guide] describes the boot flow in details.

A TD is an encrypted VM with the ability to attest to the identities of the software loaded into it. Every TD is equipped with 5 MRs (*Measurement Register*s) for attesting to the identities of loaded software. Their values can be retrieved/authencated by `TDCALL[TDG.MR.REPORT]`. <br>**Note**: The full `TDCALL` interface is documented in [Intel® TDX Module 1.0 Specification][tdx-seam-v1], Chapter 24.3.

- `MRTD` contains the static measurement, which is the cryptographic digest of the initial memory image of the TD.
- `RTMR[0..3]` contain the dynamical measurements. These MRs work in the same way as PCRs (*Platform Configuration Register*s) in a [TPM][wiki-tpm] (*Trusted Platform Mudule*). That is, they are initialized to zero and can never be written to, but can only be *extend*ed. The *extension* operation hashes the concatenation of the current value of an `RTMR` with the software supplied value and uses the resulted digest as the new value of that `RTMR`.

At a high level, the process of booting a TD is identical to booting a regular VM, plus the additional steps for measuring dynamically loaded software components. The diagram below depicts the measured components, and is excerpted from [Intel® TDX Virtual Firmware Design Guide][tdvf-guide], Chapter 8.

![TDVF Measurements](images/tdvf-measurement.svg)

As shown above,

1. The initial memory image of a TD is comprised of *Boot FV*, *Config FV*, *TD Hob*, along with small amount of additional memory serving as the temporary heap/stack. The existence of all those (measured by `SEAMCALL[TDH.MEM.PAGE.ADD]`) plus the content of *Boot FV* (measured by `SEAMCALL[TDH.MR.EXTEND]`) are measured to the TD's `MRTD`. <br>**Note**: The full `SEAMCALL` interface is documented in [Intel® TDX Module 1.0 Specification][tdx-seam-v1], Chapter 24.2.
2. The TD (or to be exact, its vCPUs) starts execution at *Boot FV*'s entrypoint (i.e., 4GB-16 bytes). *Boot FV* measures *Config FV* and *TD Hob* to `RTMR[0]` before consuming their contents.
3. After *Boot FV* finishes initialization of the TD, it loads the *OSLoader* and measures it to `RTMR[1]` before executing it.
4. The *OSLoader* is responsible for measuring to `RTMR[1]` the OS kernel along with its configurations and/or boot parameters, before launching the kernel.

Please note that ACON uses [Direct Linux Boot][qemu-doc-linuxboot], in which case *Boot FV* also acts as the *OSLoader* - i.e., *Boot FV* loads (from the [*QEMU* fw_cfg device][qemu-doc-fw_cfg]) the Linux kernel image, the initrd image and the kernel command line, and then measures them to `RTMR[1]`, and finally executes the kernel image.

The rest of this guide provides details for building kernels and initrd images suitable for booting *aTD*s (ACON TDs) using [Direct Linux Boot][qemu-doc-linuxboot].

- [Configuring Linux Kernel](#configuring-linux-kernel) details necessary/recommended features for an *aTD* kernel.
- [Customizing Initial RAM Disk](#customizing-initial-ram-disk) describes helper scripts for building/customizing initrd images suitable for booting *aTD*s.

## Configuring Linux Kernel

The TDX kernel patch is being upstreamed. Discussions in this section are based on Intel's fork at https://github.com/intel/tdx/tree/guest-next, which was based on Linux-6.4-rc1 at the time this doc was written.

### Minimal Configuration
A minimal kernel is important from both functionality and security standpoints.

- Memory consumption - TD (private) memory cannot be shared, thus a smaller kernel could save significant amount of memory, especially when the number of running TDs is large.
- Boot performance - All TD (private) memory pages must be measured, so a smaller kernel could shorten boot time.
- Reduced attack surface - By removing unused/unneeded features, adversaries would have fewer options to break into the system.

Thus, we'd like a kernel that have only the necessary features enabled. The rest of this section describes the changes upon the default `.config` file generated by `make tinyconfig`.

**Note:** `tinyconfig` is one of the default configuration targets provided by the Linux kernel build system. It initializes `.config` with the fewest features turned on.

The table below lists the minimal set of features necessary to build a TDX guest kernel.

|Config|Dependencies|Notes
|-|-|-
|`LOCALVERSION`||**Optional.**
|`LOCALVERSION_AUTO`||Linux kernel build system appends git commit ID (in the form of `-gxxxxxxxxxxxx`) to the kernel's version string, so that kernel source code can be easily found by going to github.com/intel/tdx/tree/xxxxxxxxxxxx.
|`64BIT`||TDX supports 64-bit OS's only.
|`IKCONFIG`||**Optional.** This embeds `.config` file into the kernel image.
|`BLK_DEV_INITRD`||This is required to boot off a RAM disk (via *QEMU*'s `-initrd` command line option).
|`RD_XZ`|`BLK_DEV_INITRD`|**Optional.** This adds `xz` compression support to initrd images. Individual compression algorithms may be enabled/disabled per users' preference.
|`PRINTK`||**Optional.** This helps kernel debugging. <br>**Note:** `dmesg` will stop working without this feature.
|`BUG`||**Optional.** This is enabled in most distro builds. <br>**Note:** This must be enabled as of Linux-5.18-rc3 as there are bugs in source code that breaks the build when disabled.
|`SMP`||Symmetric multi-processing is always desirable.
|`KVM_GUEST` `TDX_GUEST_DRIVER`|`HYPERVISOR_GUEST` `PARAVIRT` `X86_X2APIC` `INTEL_TDX_GUEST`|This adds TDX guest support.
|`MCORE2`||This enables instructions available on Intel Core 2 and newer processors.
|`CPU_SUP_INTEL`||Enabling this (and disabling all other processor vendors) instructs `menuconfig` to hide features not applicable to Intel processors.
|`ARCH_RANDOM`||This enables `rdrand` to be the RNG.
|`ACPI`||TDVF communicates certain platform configurations via ACPI tables. <br>**Note:** All subitems under `ACPI` are unnecessary and can be disabled safely.
|`EFI_STUB`|`ACPI` `EFI`|This is required for direct kernel boot (i.e., *QEMU*'s `-kernel` command line option). <br>**Note:** EFI stub exists in compressed kernel images only. That is, UEFI based BIOS (e.g., OVMF) boots compressed kernels only.
|`INTEL_IDLE`|`CPU_IDLE` `CPU_SUP_INTEL`|Intel idle handler can reduce host processor usage significantly when idle.
|`BINFMT_ELF` `BINFMT_SCRIPT`||Executable ELF and scripts (starting with `#!`) must be supported for obvious reasons.
|`SERIAL_8250_CONSOLE`|`TTY` `SERIAL_8250`|**Optional.** This enables `ttyS0` console and is useful for debugging the booting process and/or the kernel.
|`DEVTMPFS`||`devtmpfs` creates device special files automatically. It shall always be mounted at `/dev`.
|`PROC_FS`||`proc` shall be mounted at `/proc`.
|`SYSFS`||`sysfs` shall be mounted at `/sys`.
|`TMPFS`|`SHMEM`|This is a RAM-based file system. It's the same as `rootfs` but support size limits.

The table below summarizes additional features for running *ACON Container*s.

|Feature|Dependencies|Notes
|-|-|-
|`MULTIUSER`||Each *Container* runs under a dedicated user context.
|`IPC_NS` `PID_NS` `USER_NS`|`MULTIUSER` `NAMESPACES` `SYSVIPC` `POSIX_MQUEUE`|*Container* needs User, PID, Mount and IPC namespaces.
|`FUTEX`||*futex* is widely used in thread libraries.
|`FILE_LOCKING`||`flock()` is used by `acond` for synchronizing accesses to `RTMR`s and their measurement logs.
|`FHANDLER` `POSIX_TIMERS` `EPOLL` `SIGNALFD` `TIMERFD` `EVENTFD` `ADVISE_SYSCALLS` `USERFAULTFD` `X86_INTEL_MEMORY_PROTECTION_KEYS`||These *syscall*s could be enabled or disabled depending on target usages.
|`AIO`||A lot of server applications (including `acond`) make use of user mode schedulers that rely on asynchronous I/O.
|`UNIX`|`NET`|UNIX domain sockets are widely used as an IPC mechanism.
|`INET`|`NET`|`acond` supports communicating with the host over TCP or VSOCK sockets. So at lease one of `INET` and `VSOCKETS` must be enabled. Moreover, most existing server applications require TCP/IP support.
|`PACKET`|`NET`|`AF_PACKET` sockets are necessary for *DHCP*, so must be enabled if `INET` is enabled.
|`PNP_DHCP`|`INET` `IP_PNP`|This adds *DHCP* support, which can be activated by adding `ip=dhcp` to kernel command line.
|`IPV6`|`NET` `INET`|**Optional.** IPv6 may be necessary for some applications.
|`VSOCKETS`|`NET`|Either `INET` or `VSOCKETS` (or both) must be enabled to allow communication between `acond` and the host.
|`SYSVIPC` `POSIX_MQUEUE`|`NET`|Both IPC mechanisms are widely used by thread libraries.
|`UNIX98_PTYS`|`TTY` `VT` `CONSOLE_TRANSLATIONS` `VT_CONSOLE`|Pseudo-terminal support for console redirection. <br>**Note:** `VT_CONSOLE` must be enabled for `UNIX98_PTYS` to work, though the dependency isn't reflected in the Linux kernel build system.
|`NULL_TTY`|`TTY`|By specifying `console=ttynull` on kernel command line, this offers a measurable way (assuming kernel command line is measured) to effectively disable console I/O. <br>**Note:** `acond` redirects its *STDIO* to `/dev/null` when its `interactive` feature is turned off. So this is necessary only with `interactive` on in `acond` build. <br>**Note:** An alternative is to drop `VT` and `TTY` but that would disable `UNIX98_PTYS` as well.
|`VIRTIO_PCI`|`VIRTIO_MENU` `PCI`|This adds *virtio-pci* device support. <br>**Note:** All *virtio* devices can be exposed as PCI or MMIO devices. *QEMU*'s support on *virtio-mmio* is however incomplete, so *virtio-pci* is the best bet at the moment. <br>**Note:** All other subitems (not listed in this table) under `PCI` are unnecessary and can be disabled safely.
|`PCI_MSI`|`PCI`|*MSI* improves performance of virtually all emulated PCI devices. It's a must for *VSOCK* to work.
|`VIRTIO_VSOCKETS`|`NET` `VSOCKETS` `VIRTIO`|This enables *virtio* as the underlying transport for *VSOCK*. <br>**Note:** This depends on `VIRTIO_PCI` when using PCI transport.
|`VIRTIO_NET`|`NETDEVICES` `NET_CORE` `VIRTIO`|This is the *virtio-net* virtual NIC, and is required if `INET` is on. <br>**Note:** This depends on `VIRTIO_PCI` when using PCI transport.
|`VIRTIO_CONSOLE`|`TTY`|This enables *virtio-serial* console (typically on `hvc0`) if so desired. <br>**Note:** This also depends on `VIRTIO_PCI` when using PCI transport.
|`RANDOM_TRUST_CPU`||This credits `rdrand` as trusted entropy source for initializing kernel's *RNG* (exposed as `/dev/random` device file). That is, `/proc/sys/kernel/random/entropy_avail` will be maxed out at boot.
|`INOTIFY_USER`||Widely used for monitoring FS events.
|`OVERLAY_FS` `OVERLAY_FS_REDIRECT_DIR` `OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW`||`overlay` FS for merging FS layers.
|`CMDLINE`|`CMDLINE_BOOL`|**Optional.** This specifies the built-in kernel command line. It may include <li>`earlyprintk=ttyS0` to redirect `printk` messages to *COM1*. <li>`console=hvc0` to designate *virtio-serial* as the system console. <li>`ip=dhcp` to configure IP addresses at boot. <br>**Note:** The *QEMU* command line option `-append` can be used to append more arguments at boot time.
|`CMDLINE_OVERRIDE`|`CMDLINE_BOOL`|**Optional.** This boolean option, if turned on, causes the kernel to ignore the command line provided by the boot loader (i.e., use the built-in command line only). This is necessary for security if command line parameters supplied via *QEMU* command line are **not** measured/extended to any `RTMR`s.

Features below may be tuned for better performance.

|Feature|Notes
|-|-
|`BASE_FULL`|Patch data structures for aligned accesses.
|`CC_OPTIMIZE_FOR_PERFORMANCE`|Pass `-O2` option to C compiler.
|`NO_HZ_IDLE`|Tickless idle is almost always desirable.
|`SLAB` or `SLUB` or `SLOB`|There are choices of page allocators. `SLOB` is the smallest in size but `SLUB` is the most efficient (and popular).
|`SPARSEMEM_VMEMMAP`|This simplifies `pfn_to_page` and `page_to_pfn` operations, hence reduces overall kernel size and improves performance.
|`COMPACTION`|This reduces memory fragmentation.
|`VIRTIO_BALLOON` `BALLOON_COMPACTION`|Balloon driver. <br>**Open:** Does this have an effect on TD private pages?
|`TRANSPARENT_HUGEPAGE_MADVIES`|2MB pages speed up #PF handling, shorten page-walk time and reduce TLB use.
|`SCHED_OMIT_FRAME_POINTER`|This reduces scheduling overhead slightly.
|`HZ_100`|Lower frequency results in fewer timer interrupts.
|`PCIE_BUS_TUNE_OFF`|**Open:** Guest this doesn't apply to *virtio* devices anyway, so is turned off to simplify kernel.

Features in the table below affect security and should be turned on.

|Feature|Notes
|-|-
|`SCHED_CORE`|This allocates the whole core to the same process to defend against certain side-channel attacks. <br>**Open:** Guess this is useless in TDs, as it's easy for adversaries to schedule claimed-to-be-SMT-sibling *VCPU*s on different physical cores.
|`RETPOLINE`|This defends against Spectre attacks.
|`LEGACY_VSYSCALL_NONE`|`vsyscall` emulation prevents *KASLR* so shall be disabled.
|`X86_UMIP`|This prevents certain instructions that leaks kernel address information from executing in user mode.
|`X86_KERNEL_IBT`|This enables *Indirect Branch Tracker* in kernel code.
|`X86_INTEL_TSX_MODE_OFF`|Turn `off` to defeat certain side-channel attacks. <br>**Open:** Applicable to TDX?
|`RANDOMIZE_BASE`|Randomize kernel base address.
|`RANDOMIZE_MEMORY`|Randomize section addresses. <br>**Open:** Any impact to memory consumption?
|`SIGALTSTACK_SIZE`|This ensures the alternative stack has enough space before dispatching the signal handler.
|`DEVTMPFS_SAFE`|Add `nosuid` and `noexec` mount options to `devtmpfs` mounts.

These features are not needed but turned on by default. They could be turned off to reduce *TCB* size.

|Config|Notes
|-|-
|`SCHED_CLUSTER`|
|`SCHED_MC`|
|`SCHED_DEBUG`|
|`X86_VSYSCALL_EMULATION`
|`X86_5LEVEL`
|`CPU_ISOLATION`
|All subitems under `ACPI`
|`X86_PM_TIMER`
|`ACPI_PRMT`|Visible and enabled by default after `EFI` is enabled.
|`HALTPOLL_CPUIDLE`
|`X86_MPPARSE`|Visible and enabled by default after `EFI` is enabled.
|`LEGACY_PTYS`
|`EFIVAR_FS`
|`ISA_DMA_API`
|`PNP_DEBUG_MESSAGES`
|`INPUT_KEYBOARD`
|`INPUT_MOUSE`
|`ETHTOOL_NETLINK`
|All subitems under `PCI`
|`VIRTIO_PCI_LEGACY`
|`ETHERNET`
|`WLAN`
|`WIRELESS`
|`NETWORK_FILESYSTEMS`
|`X86_MCE_INTEL`
|`PERF_EVENTS_INTEL_*`
|`SERIO`
|`PCI_MMCONFIG`
|`PERF_EVENTS_*`|
|`DEVPORT`
|`SERIAL_8250_PCI` `SERIAL_8250_PNP` `SERIAL_8250_LPSS` `SERIAL_8250_MID` `SERIAL_8250_PERICOM`|Only legacy *COM* ports (i.e., port `0x3f8` for *COM1* and `0x2f8` for *COM2*) are used.
|`SERIAL_8250_NR_UARTS`|Default to `4` but can be set to `1`.
|`DEBUG_BUGVERBOSE`|
|`*_DIAG`|Disable all monitoring interfaces.

### Temporary Disk Storage

Temporary disk storage is desirable as it's much cheaper than RAM.

Most VMMs support providing disk storage as *virtio-blk* devices. A *virtio-blk* device can be used either as a `swap` device (to expand capacities of `tmpfs` mounts) or to host a filesystem to provide temporary file storage.

For security reasons, block devices must be confidentiality, integrity and replay pretected. Confidentiality and integrity can be protected by [`dm-crypt`][dm-crypt] and [`dm-integrity`][dm-integrity] kernel modules, while replay protection can be achieved by keeping integrity tags in memory.

The table blow lists necessary kernel configurations for encrypted/integrity-protected block devices, along with `swap` and `ext4` supports.

|Feature|Dependencies|Notes
|-|-|-
|`DM_CRYPT` `DM_INTEGRITY`|`MD` `BLK_DEV_DM`|`dm-crypt` and `dm-integrity` provide confidentiality and integrity protection for block devices.
|`CRYPTO_AES_NI_INTEL`|`CRYPTO`|*AES* implementation using Intel *AES-NI* instructions.
|`CRYPTO_SHA256_SSSE3` `CRYPTO_SHA512_SSSE3` `SHA3`|`CRYPTO`|Hash algorithms. Enabled as needed.
|`CRYPTO_CBC` `CRYPTO_XTS`|`CRYPTO`|Block cipher modes. Enable as needed.
|`CRYPTO_CMAC` `CRYPTO_HMAC`|`CRYPTO`|*MAC* (Message Authentication Code) modes. Enable as needed.
|`CRYPTO_AUTHENC`|`CRYPTO`|Combine an encryption and an authentication schemes into an *AEAD* encryption scheme. This feature is necessary to support random *IV*.
|`VIRTIO_BLK`|`BLK_DEV`|*virtio-blk* devices support. `virtio` block devices can be added to a TD/VM via `-drive` *QEMU* option along with `if=virtio` parameter.
|`SWAP`|`BLOCK`|Enables `swap` support. This also expands `tmpfs` capacity.
|`EXT4`|`BLOCK`|The `ext4` file system driver.
|`BLK_DEV_RAM`|`BLK_DEV`|[RAM disk][ramdisk] block devices are needed by [`dm-integrity`][dm-integrity] (as `meta_device`) for keeping integrity tags in memory - a means to defend against replay attacks.
|`BLK_DEV_RAM_COUNT`|`BLK_DEV_RAM`|Default number of RAM disk devices - i.e., `/dev/ram0`, `/dev/ram1`, ... <br>**Note:** This cannot be changed at runtime.
|`BLK_DEV_RAM_SIZE`|`BLK_DEV_RAM`|Default size of RAM disk devices. The required size of a RAM disk device (used by `dm-integrity` as `meta_device`) depends on the size of the block device being integrity-protected and also the integrity tag size - e.g., for a 60GB disk with 4kB sector size and 64B tag size, the RAM disk needs to be around 1GB in size. <br>**Note:** All RAM disks will be set to the same size. Actual memory however will be committed only when necessary. RAM disk size cannot be changed at runtime.
|`ZRAM`|`BLK_DEV` `CRYPTO_LZO` `CRYPTO_ZSTD` `CRYPTO_LZ4` `CRYPTO_LZ4HC` `CRYPTO_842`|[`zram`][zram] is the next generation RAM disk. It provides all features that RAM disk provides, plus<ul><li>Hot add/remove for increasing/decreasing the number of `/dev/zram*` devices at runtime. <li>Sizes can be set/reset for individual devices at runtime. <li>Support *TRIM* (like an SSD) to allow freeing unused sectors (backed by non-pageable memory). <li>Contents are compressed to save memory. Multiple compression algorithms are supported and can be changed at runtime for individual devices.</ul> **TODO:** Switch to `zram` (in future)!!! As of Linux 6.4-rc1, Linux guest exhibits instability when using `zram` as `meta_device` for (confidentiality-and-integrity-protected) `swap` devices. **This is probably a Linux kernel bug**.

### Compressing Memory (or Not)

[`zswap`][zswap] hooks into the `swap` front end to compress would-be-swapped-out pages and store them in its own memory pool. In the case the memory pool has exhausted, `zswap` picks the victum pages (depending on the compression algorithm) within its pool, decompresses them, and writes them out to `swap`. Its impact to performance varies depending on workloads. In the case of `acond`, data stored in `tmpfs` could occupy a multiple of RAM size, thus `zswap` would be able to reduce disk I/Os as more files could be kept in memory thanks to compression. However, compression/decompression adds to paging overhead. **The net impact to performance is yet to evaluate**.

## Customizing Initial RAM Disk

An initrd image must be passed to the kernel (through `-initrd` *QEMU* command line option) to be mounted at `/` when the TD boots. Then, the kernel starts `/init` as the first user mode process. In most Linux distros today `/init` is simply a shell script that loads necessary device and file system drivers to access the real root file system, then pivots root and executes the init program (typically `systemd`) in the new root directory.

initrd is a *CPIO* archive, which could be created using the standard Linux utility `cpio`.

[`initrd-helper-funcs.sh`](../scripts/initrd-helper-funcs.sh) provides *bash* functions to assist developers in creating and customizing initrd images. Simply source the script (i.e., `source path/to/acon/source/scripts/initrd-helper-funcs.sh`) to bring in those functions in the current shell.

The table below summarizes those functions.

|Function|Description
|-|-
|[`gen_initrd`](#gen_initrd)|Generates an initrd image from a `docker` container image.
|[`create_initrd`](#create_initrd)|Generates an initrd image from a to-be-initrd directory.
|[`gen_init`](#gen_init)|Generates the executable script `/init` and necessary supporting files in the specified (to-be-initrd) directory.
|[`abs2rellinks`](#abs2rellinks)|Converts symlinks of absolute paths to symlinks of relative paths.
|[`hard2symlinks`](#hard2symlinks)|Replaces hard links of a specified file with symbolic links.
|[`tar_container`](#tar_container)|Creates a *TAR* archive from a container image.
|[`cpio_initrd`](#cpio_initrd)|Creates an initrd-compatible *CPIO* archive from a directory.

Certain shell functions are also affected by environment variables. Below lists the environment variables and their affected functions.

|Environment Variable|Functions Affected|Description
|-|-|-
|`F`|`gen_initrd` `gen_init`|When generating files, `gen_initrd` and `gen_init` will skip existing files, unless `F` is set. See [`gen_init`](#gen_init) for details.
|`C`|`gen_initrd` `create_initrd`|[initrd][initrd] images are **not** compressed unless `C` is set, in which case `$C` is the suffix of the compressed archive and determines the compression utility used by `create_initrd` - e.g., `C=gz` to select `gzip`, `C=bz2` to select `bzip2`, or `C=xz` to select `xz`. See [`create_initrd`](#create_initrd) for details.
|`T`|`gen_initrd` `create_initrd` `cpio_initrd`|If set, `$T` is the timestamp to which all files' modification and access times will be set. It may be set to a string of the form `[[CC]YY]MMDDhhmm[.ss]` (see `-t` option of [`touch(1)`][man-touch.1]) for a specific date/time, or simply `.` (period) to take the default. This is designed specifically for **reproducible build** of initrd images.

### tar_container

**Synopsis:** `tar_container CONTAINER [DIR]...`

`tar_container` creates a *TAR* archive containing specified directories of a `docker` container image, and writes the archive to `stdout`.

`CONTAINER` is the container *label* (and optional *tag*) - e.g., `busybox:uclibc`, `alpine:latest`, etc. `DIR...` is a list of space-separated directories and can be omitted, in which case the default is `./`. E.g.,

- `tar_container busybox:musl > bbox.tar` results in a `bbox.tar` archive containing all directories/files of the container image labeled `busybox:musl`; while
- `tar_container alpine bin lib usr | tar -C initrd-alpine -x` effectively copies `bin/`, `lib/` and `usr/` recursively from the container image `alpine:latest` to the host directory `initrd-alpine/`.

### gen_init

**Synopsis:** `gen_init INITRD_TREE [init|profile|fstab|resolv.conf|udhcpc]`

`gen_init` generates the executable script `INITRD_TREE/init` and its dependent files.

When two or more command line arguments are given, `gen_init` works in *explicit* mode. In this mode `gen_init` generates the specified files only. Existing files will be **overwritten**. The table below lists supported arguments and the corresponding files that will be generated.

|Argument|File|Description
|-|-|-
|`init`|`INITRD_TREE/init`|Linux kernel executes `/init` as the first user mode process on boot. <br>**Note:** Internally, `/init` contains a set of shell scripts that could be sourced by `. /init` after boot. Please see the generated `/init` script for more details.
|`profile`|`INITRD_TREE/etc/profile`|`sh` configuration file - see the generated file for details.
|`fstab`|`INITRD_TREE/etc/fstab`|`/init` mounts file systems and/or `swap` devices per entries in `/etc/fstab`  - see the generated file for details.
|`resolv.conf`|`/etc/resolv.conf`|`gen_init` simply delete this file and `/init` will symlink it to `/proc/net/pnp`.
|`udhcpc`|`/usr/share/udhcpc/default.script`|This is the configuration script invoked by `udhcpc` for configuring the TCP/IP stack.

When only one argument (i.e. `INITRD_TREE`) is given, `gen_init` works in *implicit* mode. In this mode,

```sh
gen_init INITRD_TREE
```

is equivalent to

```sh
gen_init INITRD_TREE init profile fstab resolv.conf
```

except that existing files will be **skipped**. This behavior could be overridden by setting the environment variable `F` to any non-nil string - e.g., `F=1 gen_init INITRD_TREE` will overwrite any existing `/init`, `/etc/profile`, `/etc/fstab` and delete `/etc/resolv.conf`. Given [`gen_initrd`](#gen_initrd) invokes `gen_init` as a subroutine, `F=1` could also be set when invoking `gen_initrd` to force regeneration of all files listed above. For example, the commmand below generates an initrd image named `initrd-alpine.cpio` from the `alpine` docker container image.

```sh
F=1 gen_initrd alpine alpine
```

Please note `gen_init` will check for the existence of and warn on missing Linux utilities that may be needed by `/init`. Some utilities (e.g., [`dmsetup(8)`][man-dmsetup.8]) are necessary for certain features (e.g., disk encryption) only, thus a warning can be safely ignored if the corresponding feature is not configured.

### cpio_initrd

**Synopsis:** `cpio_initrd INITRD_TREE`

`cpio_initrd` creates a *CPIO* archive from the directory specified by `INITRD_TREE` and writes it to `stdout`. Please note that `cpio_initrd` checks the existence of `INITRD_TREE/init`, `INITRD_TREE/sbin/init`, `INITRD_TREE/etc/init` or `INITRD_TREE/bin/init`, and errs if none exists.

*CPIO* archives store *mtime* (modification time) for all files, and that has prevented reproducible builds. `cpio_initrd` can optionally reset *mtime*s before creating the *CPIO* archive. To do so, just set the environment variable `T` to the desired timestamp (whose format is the same as accepted by `-t` option of [`touch(1)`][man-touch.1]) in UTC, or simply `.` to take the default time `0001010000`, which is midnight Jan 1, 2000 UTC. E.g.,

```sh
T=. cpio_initrd alpine
```

sets *mtime* of all files under `alpine/` to Jan 1, 2000 UTC before creating and writing the *CPIO* archive to *stdout*.

Given both [`create_initrd`](#create_initrd) and [`gen_initrd`](#gen_initrd) invoke `cpio_initrd` as a subroutine, `T` works for all those 3 functions. E.g.,

```sh
T=2012310000 create_initrd alpine
```

sets *mtime* of all files under `alpine/` to Dec 31, 2020 UTC, and then creates the initrd image `initrd-alpine.cpio`.

### create_initrd

**Synopsis:** `create_initrd INITRD_TREE [INITRD_IMAGE]`

This is a shorthand for `cpio_initrd INITRD_TREE > INITRD_IMAGE`. If `INITRD_IMAGE` is omitted, it is default to `INITRD_TREE/../initrd-DIRNAME.cpio`, where `DIRNAME` is the last (rightmost) component of `INITRD_TREE`.

initrd images are **not** compressed by default. To create a compressed initrd image, set environment variable `C` to the suffix of the compressed archive. E.g.,

```sh
C=xz create_initrd alpine
```

creates a compressed (by `xz`) initrd image named `initrd-alpine.cpio.xz`.

Other supported compressed archive suffices are `gz` and `bz2`.

Given [`gen_initrd`](#gen_initrd) invokes `create_initrd` as a subroutine, `C` could also be set when invoking `gen_initrd` to generate a compressed initrd image directly. For example, to generate and compress a reproducible initrd image using `bzip2` from `alpine` container with regeneration of all configuration files, use the command below.

```sh
C=bz2 F=1 T=. gen_initrd alpine alpine
```

### gen_initrd

**Synopsis:** `gen_initrd INITRD_TREE CONTAINER [SOURCE_DIR]...`

This combines [`tar_container`](#tar_container), [`gen_init`](#gen_init), and [`create_initrd`](#create_initrd) in one shot. E.g.,

```sh
C=xz F=1 T=. gen_initrd alpine alpine`
```

does all the following in one shot:

- Creates `$PWD/alpine/`, and copies to it recursively all files from the container image labeled `alpine`.
- Generates `$PWD/alpine/init` along with its dependencies.
- Sets *mtime* of all files under `$PWD/alpine/` to the default, and generates the final compressed initrd image - `$PWD/initrd-alpine.cpio.xz`.

### abs2rellinks

**Synopsis:** `abs2rellinks ROOT`

`abs2rellinks` replaces all symlinks of absolute paths with symlinks of relative paths, with `/` mapped to `ROOT`.

### hard2symlinks

**Synopsis:** `hard2symlinks FILE [DIR]`

`hard2symlinks` replaces all hard links to `FILE` with symlinks in `DIR`, which is default to the directory containing `FILE` if omitted.

## QEMU Command Line for Launching TD

[`start-qemu.sh`](../scripts/start-qemu.sh) is a sample script intended to demonstrate the use of *QEMU* for creating regular VMs or TDs suitable for hosting *ACON Containers*.

The table below explains all *QEMU* options used by [`start-qemu.sh`](../scripts/start-qemu.sh).

|Option|Explanation
|-|-
|`-nographic`|This turns off *QEMU*'s GUI (Graphical User Interface).
|`-accel kvm`|This specifies `kvm` as the accelerator to create a native VM (instead of emulated execution of instructions).
| `-object tdx-guest,id=tdx`|This creates an object of type `tdx-guest`, and names it as `tdx`. The object can then be referred to by `-machine` to host the VM, which in our case will be a TD.
|`-object memory-backend-memfd-private,id=ram1,size=${M:-2g}`|This specifies the maximal size of memory that could be allocated to the TD. This size **must** be the same as the size passed to `-m` option.
|`-machine q35,memory-backend=ram1,kernel_irqchip=split,confidential-guest-support=tdx`|A `machine` is a predefined set of emulated devices and chipset. This option instructs *QEMU* to emulate a `q35` machine. `memory-backend=ram1` sets the memory size implicitly, while  `confidential-guest-support=tdx` selects the `tdx` object created previously for hosting the VM. <br>**Open:** What is `kernel_irqchip=split`?
|`-cpu host,-kvm-steal-time,pmu=off`|`host` passes through all features supported by the physical processors to the VM. <br>**Open:** What are `-kvm-steal-time` and `pmu=off`?
|`${VP:+-smp $VP}`|This specifies the number of virtual processors when `VP` is defined.
|`-m ${M:-2g}`|This specifies the VM memory size to be `$M`, or `2g` if `M` is not defined.
|`-nodefaults`|Removes all default devices from `q35`.
|`-vga none`|Turns off VGA emulation. Hence, the guest will not have display.
|`-no-hpet`|Turns off *HPET* (**H**igh-**P**recision **E**vent **T**imer).
|`-nic user,model=virtio,ipv6=off,ipv4=on,hostname=${TD:+td-}${TD:-vm}$(host_fwd $TCPFWD)`|This adds a virtual *NIC* (**N**etwork **I**nterface **C**ard) to the VM. <ul><li>`user` configures user mode host network backend - i.e., *QEMU* acts a *NAT* gateway so that all connections originated from the guest would look like originated from the *QEMU* process. <li>`model=virtio` emulates the *NIC* as a *virtio-net* NIC connected to the PCI bus. <li>`ipv6=off` turns off *DHCP* for *IPv6*. <li>`ipv4=on` turns on *DHCP* for *IPv4*. <li>`hostname=${TD:+td-}${TD:-vm}` sets the host name (as a *DHCP* option) to be `vm` for a regular VM, or `td-$TD` for a TD. <li>`$(host_fwd $TCPFWD)` configures *TCP* port forwarding. `TCPFWD` has been described [earlier](#launching-td) in this guide.</ul> **Note:** More details available in [*QEMU* doc][qemu-doc-net].
|`${CID:+-device vhost-vsock-pci,guest-cid=$(test $CID -gt 2 && echo $CID \|\| echo $$)}`|This adds *VSOCK* as *virtio-pci* device. `guest-cid=` option specifies the *CID*.
|`-bios ${BIOS:-/usr/share/qemu/OVMF.fd}`|This specifies the BIOS image. By default *QEMU* uses `qboot`, which isn't compatible with *TDX*.
|`-chardev stdio,id=mux,mux=on,signal=off`|This creates a character device backend (`chardev`) on *QEMU*'s `stdio`. <ul><li>`id=mux` names this `chardev` backend as `mux`. Thus, it could be referred to as `chardev:mux` later on. <li>`mux=on` enables multiplexing. A multiplexed `chardev` backend can serve up to 4 emulated character devices in the guest. <li>`signal=off` instructs *QEMU* **not** to handle signals but to pass through the keystrokes (e.g., `^C`, `^D`, `^Z`, etc.) to the guest.</ul> **Note:** *QEMU* supports [keyboard shortcuts][qemu-doc-key] in `chardev` backend multiplexer for switching among frontends.
|`-device virtio-serial,max_ports=1 -device virtconsole,chardev=mux`|This creates a single-port *virtio-serial* device. <ul><li>`-device virtio-serial,max_ports=1` emulates a PCI serial device that has only one serial port. <li>Each `-device virtconsole,chardev=mux` adds a serial port to the device defined above. `chardev=mux` specifies `mux` (defined above) as the serial port's backend.</ul>
|`-serial chardev:mux`|This enables the legacy serial port (aka. `COM1`) and specifies `mux` as its backend.
|`-monitor chardev:mux`|This enables [*QEMU* monitor][qemu-doc-mon] and specifies `mux` as its backend.
|`-append \"ip=dhcp console=hvc0 earlyprintk=ttyS0 $KA\"`|This gives the kernel command line. One can define `KA` to pass more parameters.
|`-initrd ${RD:-$(dirname $0)/initrd}`|This specifies the initrd image file.
|`-kernel "${@:-$(dirname $0)/vmlinuz}"`|This specifies the kernel image, along with additional command line parameteres (if any) to be passed to *QEMU*.

[`start-qemu.sh`](../scripts/start-qemu.sh) allows customizing its behavior via environment variables, which have been detailed [earlier](#launching-td) in this guide.

[file-config-acon]: config-acon
[qemu-cmdline]: #qemu-command-line-for-launching-td
[qemu-doc-net]: https://www.qemu.org/docs/master/system/invocation.html#hxtool-5
[qemu-doc-mon]: https://www.qemu.org/docs/master/system/monitor.html
[qemu-doc-key]: https://www.qemu.org/docs/master/system/mux-chardev.html
[qemu-doc-linuxboot]: https://qemu-project.gitlab.io/qemu/system/linuxboot.html
[qemu-doc-fw_cfg]: https://www.qemu.org/docs/master/specs/fw_cfg.html
[initrd]:https://docs.kernel.org/admin-guide/initrd.html
[ramdisk]:https://www.kernel.org/doc/html/latest/admin-guide/blockdev/ramdisk.html
[zram]:https://docs.kernel.org/admin-guide/blockdev/zram.html
[zswap]:https://www.kernel.org/doc/html/latest/admin-guide/mm/zswap.html
[linux-crypto]:https://www.kernel.org/doc/html/latest/crypto/
[dm-crypt]: https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-crypt.html
[dm-integrity]: https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-integrity.html
[man-dmsetup.8]: https://man7.org/linux/man-pages/man8/dmsetup.8.html
[man-touch.1]: https://man7.org/linux/man-pages/man1/touch.1.html
[intel-tdx]: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html
[tdvf-guide]: https://cdrdv2.intel.com/v1/dl/getContent/733585
[tdx-seam-v1]: https://cdrdv2.intel.com/v1/dl/getContent/733568
[wiki-tpm]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
