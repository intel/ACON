# Sample ACON client side application 

This directory contains the souce code of a sample ACON client side application. 

The client side application works with the server side running inside an ACON container to retrive the TD quote, measurement logs and additional attestation data. It will dump the quote into a binary file named `quote.bin`, store RTMR logs and report data in a JSON format file named `quote.json` and display additional information such as ACON container ID, attestation data etc. With these data from server side, client side can verify the quote, check whether RTMR values match between the one embedded in the quote and the one calculated from the measurement logs. In addition, it can check whether the attestation data is expected.

The `app` executable file in this directory is reponsible for verifying the quote. It is built from the [quote verification sample code](https://github.com/intel-innersource/frameworks.security.confidential-computing.tee.dcap-trunk/tree/master/dcap_source/SampleCode/QuoteVerificationSample) within the [DCAP project](https://github.com/intel-innersource/frameworks.security.confidential-computing.tee.dcap-trunk). You can build it by yourself with the DCAP stack following the build instrcutions. The executable file provided here is only meant to make it easier to run the sample application.

## Build and clean the sample application

The sample application is written in Go, `go build` will build out the client application named `sampleclient`. `go clean` will clean the application.

## Run the application

In order to make the application work, we need to bring up the server part first. The running server is actually an ACON container so it can be launched by the `aconcli run` command. The `sample-acon-startvm` file here is a QEMU VM start script which can be used as a reference when launching the server.

Once the server is launched, we can run the client application by invoking `./sampleclient`.