# Remote Attestation Sample Code

This directory contains sample source code to demonstrate how remote attestation works in ACON containers. More information on TDX remote attestation can be found at https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf.

This sample is comprised of a server and a client that communicate with each other over TCP. The server is an ACON container that generates TDX quotes upon requests from the client, which is a command line application running in the host.

The client works with the server to retrieve a TD quote, along with the measurement logs and additional attestation data. It then verifies the quote, checks if RTMR values in the quote match those calculated from the measurement logs and if the server has attached the expected attestation data, and finally decodes/displays everything it receives. Additionally, the quote is written to `quote.bin`, while RTMR logs and report data are written to `quote.json`.

Simply type `make` to build both the server and the client. `docker`, `openssl`, and [`aconcli`](../../doc/GettingStarted.md#building-aconcli) are required in the build process.

Running the sample requires a TDX enabled platform.

- The server must be started first, by

  ```sh
  TCP_PORT=5555 ATD=1 ATD_TCPFWD=8080:8085 ATD_KERNEL=/path/to/vmlinuz ATD_RD=/path/to/initrd.img aconcli run -ni -c:$TCP_PORT server.json
  ```

  **Note**: `TCP_PORT` and `ATD` could be substituted by whatever deemed appropriate by the user. `ATD_TCPFWD` specifies TCP port forwarding rules and is in the form of `HOST_PORT:GUEST_PORT`. To make the same work, `GUEST_PORT` **must** be set to `8085`, while `HOST_PORT` should be set to the same value as passed to the client application on its command line. `ATD_KERNEL` and `ATD_RD` should be set to the file paths to the guest kernel and initrd image, respectively.

- Given `ATD_TCPFWD=8080:8085` when starting the server, the client should be started by

  ```sh
  client/sampleclient 8080
  ```

  **Note**: The `app` executable in the [client/](client/) directory is required for verifying the quote. It is built from the [quote verification sample code](https://github.com/intel-innersource/frameworks.security.confidential-computing.tee.dcap-trunk/tree/master/dcap_source/SampleCode/QuoteVerificationSample) of  [DCAP](https://github.com/intel-innersource/frameworks.security.confidential-computing.tee.dcap-trunk) and is provided here for the users' convenience (so that DCAP wouldn't have to be built/installed for building this sample).