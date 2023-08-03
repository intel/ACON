# Attested Container (ACON) Command Line Application

## Development Environment Setup

To build and run `aconcli`, you need Golang, protocol buffer, and Go plugins for protocol compiler.

- For Golang, please refer to the installation document [here](https://go.dev/doc/install). Version 1.20.6 and higher is recommended.

- For protocol buffer and Go plugins, please refer to the installation guide listed [here](https://grpc.io/docs/languages/go/quickstart/).

## Build, install and clean the aconcli project

To build `aconcli` project, change to the project's top level directory:

`$ go generate && go build`

To clean up:

`$ go clean`

## Running the aconcli tool

All supported `aconcli` usages and detailed descriptions can be found [here](https://github.com/intel-innersource/frameworks.security.confidential-computing.tee.td-enclave/blob/master/doc/Utility.md).

## About the sample ACON-VM start sript

With `aconcli`, a sample ACON-VM start script is provided. This is used by `aconcli` to launch a ACON-VM. Environment variables are used in this script file to set up the virtual machine. Users can provide their own start script while adhering to the semantics of these environment variables.

The environment variables being used are:

- ACON_STARTVM_PARAM_VP_NUM: Number of virtual CPU, default to 4

- ACON_STARTVM_PARAM_MEM: Memory size of the virtual machine, default to 2 GB

- ACON_STARTVM_PARAM_KA: Additional kernel arguments, default to empty

- ACON_STARTVM_PARAM_TCPFWD: TCP host forward setting. `aconcli` will be responsible for setting it up according to the argument user provides when invoking it.

- ACON_STARTVM_PARAM_RAMDISK: Location of the init ramdisk image. If omitted, the ramdisk named 'initrd.img' will be searched in the same directory as `aconcli` executable.

- ACON_STARTVM_PARAM_KERNEL: Location of the VM kernel image. If omitted, the kernel image named 'kernel.img' will be searched in the same directory as `aconcli` executable

- TD: Non-empty string indicates that TDX should be enabled in the virtual machine and the hostname will be 'acon-${TD}'. Default to empty string, which means TDX will not be enabled.

- CID: VSOCK CID of the virual machine. Need to specify it when user chooses VSOCK to connect to `acond`.
 
