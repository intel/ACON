# ACON Image

ACON image is the center of the ACON architecture. [`aconcli`](../aconcli/README.md) (ACON Command Line Interface) generates, manipulates and signs ACON images, while [`acond`](../acond/README.md) (ACON Daemon) receives, measures and launches ACON containers from ACON images.

**Note**: Audience familiar with [OCI image spec][oci-image-spec] may find ACON images and OCI images similar. However, ACON images have some unique features as highlighted in [README](../README.md#architecture-overview).

An ACON image at a high level consists of the following:

- ACON manifest - A JSON file that contains among other things, the *Launch Policy* and references to *FS (Filesystem) Layer*s. All ACON manifests must be digitally signed.
- *FS Layer*s - Directory trees to be merged by `overlay` filesystem to form the *ACON container*'s directory tree. Like OCI, *FS layer*s are stored in *TAR* (*T*ape *AR*chive) format (aka. *tarball*s). <br>**Note**: *FS layer* compresion or encryption is not supported currently, but may be added in future.

To be concise, ACON image, ACON manifest and ACON container are simply referred to as *Image*, *Manifest* and *Container* in *italics*, respectively, throughout the rest of this document.

## Manifest

A *Manifest* defines an *Image* and is represented as a JSON file. Below is an example *Manifest*.

```json
{
  "aconSpecVersion": [
    1,
    0
  ],
  "layers": [
    "signer/sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/SomeSharedLayer:2",
    "sha256/e67648e77428fe38272e3ebe300cf16607e2b0f7cba5e197f741d4a941e0c386",
    "sha384/8bf8dbf9f3c6e29660adf60f0eff64e6f2d47bf789d848386e6d2a644d5cf047d2bc06778f88e74f917a2dae41f641b8"
  ],
  "aliases": {
    "contents": {
      "sha256/e67648e77428fe38272e3ebe300cf16607e2b0f7cba5e197f741d4a941e0c386": [
        "SharedLayerA:1",
        "SharedLayerA:0"
      ],
      "sha224/22dde86581f879abc2e77f1fff4a9da0654f846bc2744fe9ad361cb9": [
        "SharedLayerB:0"
      ],
      "signer/sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/SomeSharedLayer:2": [
        "SharedLayerC:2",
        "SharedLayerC:1",
        "SharedLayerC:0"
      ]
    },
    "self": {
      ".": [
        "SomeProduct:1",
        "SomeProduct:0"
      ]
    }
  },
  "entrypoint": [
    "/path/to/executable",
    "arg1",
    "arg2",
    "..."
  ],
  "env": [
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "HTTPS_PROXY",
    "TRAFFIC_LIGHT=",
    "TRAFFIC_LIGHT=Red",
    "TRAFFIC_LIGHT=Yellow",
    "TRAFFIC_LIGHT=Green"
  ],
  "workingDir": "/work",
  "uids": [
    101,
    201
  ],
  "logFDs": [
    1,
    2
  ],
  "writableFS": true,
  "noRestart": false,
  "signals": [
    -15,
    -18,
    -19
  ],
  "maxInstances": 1,
  "policy": {
    "accepts": [
      "sha256/c4c56a4bfe7a48ca831492c67cd68537ba46fd89876262f9a5ee5547466a94a8/ProductA:2",
      "sha256/c4c56a4bfe7a48ca831492c67cd68537ba46fd89876262f9a5ee5547466a94a8/ProductB:1",
      "sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/*",
      "sha384/*/4c1c3713b0c3d7fd36750e51f28c8f123dfcad9e506cbfd5d06432cdf2df4194327442571e805ca5b46c7ab151ead3cd"
    ],
    "rejectUnaccepted": true
  }
}
```

The table below summarizes top-level fields of a *Manifest* that have been defined (so far).

|Field|Type|Description
|-|-|-
|`aconSpecVersion`|*Array*|Version of this spec in the form of `[ MAJOR, MINOR ]`, and should be `[ 1, 0 ]` for version `1.0`.
|`layers`|*Array*|This is the list of *FS layer*s to be combined by `overlay` to form the *Container*'s directory tree. *FS layer*s must be listed in lower-layer-first order - i.e., the last entry of `layers` will appear first/leftmost in the `:`-separated directory list passed to `lowerdir=` option when mounting the `overlay` filesystem. See [Filesystem Layers](#filesystem-layers) for details. <br>**Note**: This field is **not** required for non-executable *Image*s.
|`aliases`|*Object*|This optional field defines [*Alias*es](#aliases) of other objects. At the moments, *Alias*es are supported for *FS layer*s and *Image*s.
|`entrypoint`|*Array*|This array specifies the path of the *Image*'s entry point along with its command line arguments. That is, when invoking [`execve(2)`][man-execve.2], <ul><li>Its first parameter (*`pathname`*) shall be set to the first element of `entrypoint`. <li>Its second parameter (*`argv`*) shall be set to the whole `entrypoint` array. <li>Its third/last parameter (*`envp`*) shall be set to an array of environment variables satisfying the constraints set forth by the `env` array described in the next row.
|`env`|*Array*|List of environment variables (and optionally their acceptable values) settable by untrusted code when executing this *Image*'s entry point. See [Execution Environment](#execution-environment) below for details.
|`workingDir`|*String*|This is the working directory in which the *Image*'s entry point should be executed.
|`uids`|*Array*|These are additional *UID*s that can be switched to using [`setuid(2)`][man-setuid.2] and [`seteuid(2)`][man-seteuid.2] inside a *Container* (launched from this *Image*).
|`logFDs`|*Array*|This field lists file descriptors whose outputs contain no secrets and can be revealed to untrusted entities. Outputs from these file descriptors may be captured by `acond` and made available to untrusted entities through `acond`'s external interface.
|`writableFS`|*Boolean*|`true` to allow a *Container* to write to its directory tree, default `false`.
|`noRestart`|*Boolean*|`true` to forbid a *Container* from being restarted, default `false`. <br>**Note**: A *Container* can be restarted only after having exited. If the *Container* is running and `signals` (described in the next row) is not empty, the signal specified as the first element of `signals` will be sent (by `acond`) in an effort to kill the *Container*.
|`signals`|*Array*|This specifies the signals allowed to be sent by untrusted code. By default, this array is empty - i.e., no signals are allowed. The first element of this array is also the signal to be sent (by `acond`) when restarting a *Container* (see `noRestart` in the row above). Each element (denoted by `signum` below) must be an integer and may be <ul><li>Positive - `signum` is allowed and when sent, will target the process of PID `1` within the *Container*. <li>Negative - `-signum` is allowed and when sent, will target the whole process group rooted at PID `1` (i.e., the process `1` and all of its descendants) within the *Container*. <li>Zero - No signal. This is meaningful only as the first element, to indicate that no signal should be sent (by `acond`) upon restarting the *Container*.</ul> Pause/Resume can be allowed/enabled by adding `SIGSTOP` (`19`) and `SIGCONT` (`18`) to this list. Please note the example [*Manifest*](#manifest) specifies `-18` and `-19` for broadcasting those signals to the whole process group.
|`maxInstances`|*Number* |This must be an integer and is the maximal number of *Container* instances that can be launched from this *Image* simultaneously, default `1` (singleton). `0` indicates no limit.
|`policy`      |*Object* |Specifies the [Launch Policy](#launch-policy) that determines what other *Image*s may share the same *aTD* (ACON TD) with this *Image*.

<details>
<summary><strong>TODO</strong>: How to allow <em>Image</em> vendors to pass additional info to appraisers safely?</summary>Options:

1. Ignore all unrecognized top-level fields. Pro: Easy. Con: Removed fields (in future specs) will be silently igored.
2. Ignore fields of particular names. Candidates: `attributes` (that we had before), `vendorSpecific`, `custom`, etc.
3. Ignore fields matching a particular pattern. E.g., all fields starting with `_`.
</details>

## Signing

Signing an *Image* is done by signing its *Manifest*. External objects (e.g., *FS layer*s) do not have to be signed explicitly as their (cryptographic) digests are included in the *Manifest*.

Given there may be multiple equivalent text representations for any JSON object, *Manifest*s shall be canonicalized before hashed. [`jq`][jq-doc] provides a convenient way for canonicalizing JSON.

<details>
<summary><strong>Example</strong>: Canonicalize JSON using <code>jq</code></summary>

The command below is an exmaple to canonicalize a JSON file (`acon-manifest.json`) using `jq`, with the result written to `stdout`.

```sh
jq -jcS . acon-manifest.json
```

Among the `jq` command line options (`-jcS`) above, `S` sorts fields alphabetically, `c` removes all insignificant spaces and newlines between fields, while `j` removes the trailing newline. All implementations should canonicalize a *Manifest* as if it were done by `jq` with `-jcS` applied, before hashing.
</details>

Signing requires a private key, which could be generated by `openssl` or similar cryptographic libraries/utilities. [ECDSA-384][nist.fips.186-5] with SHA-384 is recommended.

<details id="sign-ex2">
<summary><strong>Example</strong>: Generate an ECDSA key pair then sign/verify a <em>Manifest</em> using <code>openssl</code></summary>

Below uses the `openssl` utility to create a random ECDSA-384 private key and save it to `signer.pem`.

```sh
openssl ecparam -name secp384r1 -genkey -out signer.pem
```

The following command canonicalizes `acon-manifest.json`, signs it with the private key created above (`singer.pem`), and writes out the signature to a file named `signature`. `-sha384` selects SHA-384 as the hash algorithm to be used in the signature.

```sh
jq -jcS . acon-manifest.json | openssl dgst -sha384 -sign signer.pem -out signature
```

The command below verifies `acon-manifest.json` against `signature` using the private key file `signer.pem`.

```sh
jq -jcS . acon-manifest.json | openssl dgst -sha384 -prverify signer.pem -signature signature
```
</details>

### Signing Certificate Generation

A verifier requires the certificate (i.e. certified public key) of a signing private key to verify any signatures generated by that private key.

There exist a variety of file formats for encoding certificates. ACON uses *DER* (*Distinguished Encoding Rules*) exclusively for its conciseness.

Self-signed certificates can be used for testing purposes.

<details>
<summary><strong>Exmaple</strong>: Create a self-signed certificate using <code>openssl</code></summary>

The command below creates a self-signed certificate for the private key file [`signer.pem`](#sign-ex2) generated previously. The command line option `-outform der` selects *DER* as the output file format.

```sh
openssl req -x509 -sha384 -key signer.pem -outform der -out signer.cer
```
</details>

For production, the signing key must be certified by a *CA* (*Certificate Authority*), which is usually a 2-step process.

1. The private key owner creates a *CSR* ([Certificate Signing Request][wiki-csr]) that contains the public key along with information about the owner and the usage of the key. The *CSR* is then sent to the *CA*.

   <details id="sign-ex4">
   <summary><strong>Example</strong>: Create a <em>CSR</em> using <code>openssl</code></summary>

   ```sh
   openssl req -new -sha384 -key signer.pem -out signer.req
   ```

   In the command above, [`signer.pem`](#sign-ex2) is the private key file on input, and `signer.req` contains the *CSR* on output.
   </details>

2. The *CA* verifies the *CSR* (e.g., verifies the owner's identity and possession of the private key) and issues a certificate based on the *CSR*.

   <details id="sign-ex5">
   <summary><strong>Example</strong>: Issue a certificate on a *CSR* using <code>openssl</code></summary>

   ```sh
   openssl x509 -req -sha384 -in signer.req -CA ca.cer -CAkey ca.pem -CAcreateserial -outform der -out signer.cer
   ```

   In the command above, [`signer.req`](#sign-ex4) is the *CSR* on input and `signer.cer` contains the certificate on output. `ca.cer` and `ca.pem` contain the *CA*'s certificate and issuing private key, respectively. `-sha384` selects SHA-384 as the hash algorithm and `-outform der` selects *DER* as the certificate file format.
   </details>

The certificate can then be used to verify signatures created by the corresponding private key.

<details>
<summary><strong>Example</strong>: Verify a <em>Manifest</em> against its signature and signing certificate using <code>openssl</code></summary>

```sh
jq -jcS . acon-manifest.json | openssl dgst -sha384 -verify <(openssl x509 -in signer.cer -inform der -pubkey -noout) -signature signature
```

[`signer.cer`](#sign-ex5) and [`signature`](#sign-ex2) above are the signing certificate and signature files on input. `-inform der` specifies `DER` as the certificate file format. The same hash algorithm must be selected at both signature creation and verification, therefore `-sha384` is specified in both places.

</details>

**Note**: Though `openssl` has been used exclusively in the examples, it's up to the implementation to choose crypto libraries and/or how to interface with them (i.e., invoking library APIs vs. command line utilities).

### Cryptographic Algorithm Selection

Given only the weakest link matters in security, only algorithms of roughly the same strength should be used together.

#### Hash

Hash algorithms are used in various places in ACON. The table below lists hash usages along with who/how to determine the algorithms.

<table>
<thead><tr>
  <th>Usage</th>
  <th>Algorithm</th>
</tr></thead>

<tr>
  <td>
<details><summary><em>FS layer</em> - <code>HASH/FSLAYER</code></summary>

- `HASH` - Name of the hash algorithm - e.g., `sha384`, `sha512`, etc.
- `FSLAYER` - Hexadecimal representation of the digest of the *FS layer tarball* under `HASH`.</td>
    <td>
SHA-384 or stronger - The *Image* vendor decides the hash algorithm.</td>

<tr>
  <td>
<details><summary>Signing/Verifying <em>Image</em>s</summary>

Signatures are always computed on the digest of the *Manifest* instead of the *Manifest* itself. Most signature algorithms (e.g., ECDSA) allow users to choose a hash algorithm, while others (e.g., EdDSA) mandate it.</td>
    <td rowspan="3">
Deduced (by `acond` and all *Image* vendors) from the signing certificate - i.e., if the signing algorithm is

- [EdDSA][wiki-eddsa] - Use the hash algorithm mandated by the signature algorithm spec - e.g., [Ed25519][wiki-ed25519] mandates SHA-512.
- Otherwise, use the hash algorithm used by the *CA* when signing this certificate.
  <br>**Note**: The hash algorithm used by the *CA* is encoded in the certificate itself. See [below](#sign-ex7) on how to determine the hash algorithm using `openssl`.

<details><summary>Why?</summary>

IDs should be unambiguous - i.e., there should be an unambiguous way to determine one hash algorithm to derive an ID.

A signature binds whatever defined in a *Manifest* (identified by its digest) to its vendor (identified by its certificate, hence *Signer ID*). The integrity of a *Manifest* is no stronger than its signature (because otherwise adversaries would target the signature instead of the hash). Therefore, the same hash algorithm as used in the signature is used to hash the signing certificate - i.e., to derive the *Signer ID*.

A signature is no stronger than the *CA*'s signature on the certificate (because otherwise adversaries would target the *CA*'s signature). Hence, the same hash algorithm used by the *CA* is used to sign *Manifest*s.

**Bottom Line**: The hash algorithm used in signing a *Manifest* is also used to derive *Signer ID* and *Image ID*. And that hash algorithm should be the same as the one used by the *CA* unless the signature algorithm has mandated a different hash algorithm.</td>

<tr id="sign-signerid">
  <td>
<details><summary><em>Signer ID</em> - <code>HASH/SIGNER</code></summary>

`HASH` - Name of the hash algorithm - e.g., `sha384`, `sha512`, etc.
`SIGNER` - Hexadecimal representation of the digest of the signing certificate under `HASH`.

*Signer ID*s never appear alone but used in

- *Alias*es - `signer/HASH/SIGNER/ALIAS`
- *Image ID*s, see [row below](#sign-imageid).</td>

<tr id="sign-imageid">
  <td>
<details><summary><em>Image ID</em> - <code>HASH/SIGNER/MANIFEST</code></summary>

- `HASH/SIGNER` - *Signer ID*, see [row above](#sign-signerid).
- `MANIFEST` - Hexadecimal representation of the digest of the *Image Manifest* under `HASH`.

*Image ID*s are used by `acond` APIs to uniquely identify loaded *Image*s and also used in [Launch Policy](#launch-policy) evaluation.</td>

</table>

**Note**: Given TDX uses SHA-384 exclusively, `acond` reject hash algorithms weaker than SHA-384 - e.g., *FS layer*s hashed by SHA-256 will be rejected. Certificates signed by SHA-256 will also be rejected.

Hash algorithm used by the *CA* in signing a certificate is encoded in the certificate itself, and can be extracted by most cryptographic libraries/tools.

<details id="sign-ex7">
<summary><strong>Example</strong>: Display the hash algorithm used in signing a certificate using <code>openssl</code></summary>

The command below displays the signing algorithm used by the *CA* when issuing the certificate (provided in a shell here-document).

```sh
openssl x509 -noout -text << EOF | awk '/Signature Algorithm:/ { print $3; exit; }'
-----BEGIN CERTIFICATE-----
MIICUjCCAbSgAwIBAgIUJAjkbgUxkY3P9JT0tadLHAkJ6bcwCgYIKoZIzj0EAwMw
OzELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjEOMAwGA1UECgwFSW50ZWwx
CzAJBgNVBAsMAlMzMB4XDTIyMDEyMjAxMzgzN1oXDTIzMDEyMTAxMzgzN1owOzEL
MAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjEOMAwGA1UECgwFSW50ZWwxCzAJ
BgNVBAsMAlMzMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAhvqa03+K932juAjI
tOZ3exqsXtK0Xn9xeVWhOtWXKcDT0lLp3aQ7WHWClfV04E2Gy87p/AfKBib5lMQg
561jCH8B5EI9YHZkAIWNrbREX5riSsIwu1NYU7DLWblPHISlo4tbF4YwYbYXxyc5
S2EbiaXouzzC6Y8iUtp8MYyOKAErK46jUzBRMB0GA1UdDgQWBBQiF6Cce8pf4QY0
tcyKrkkOFPTj5zAfBgNVHSMEGDAWgBQiF6Cce8pf4QY0tcyKrkkOFPTj5zAPBgNV
HRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA4GLADCBhwJBTdlFTOLcYxbw9YnT0Jpd
O10m8PiSUqSrFEJUfngMygeSnR1RNVHf4lfPj0sGuRPjtXS2T8JPcwY53Fl83GNC
5v4CQgDDaG3ITSqeMOsFjLU+hzhDFFxnGtCeroayxzRhBHHkz2zKWQyEq32+47ms
cMKBvNft1M7aNhB87oxhP7YA73otiw==
-----END CERTIFICATE-----
EOF
```

The output should resemble the following, meaning the certificate on input was signed by an ECDSA key with SHA-384 as the hash algorithm.

```
ecdsa-with-SHA384
```

**Note**: `openssl` doesn't display the hash algorithm for those signature algorithms (e.g., [`Ed25519`][wiki-ed25519]) that don't offer choices of hash algorithms.

</details>

#### Digital Signature

There are two applications of digital signatures in the signing process - one for signing the *Manifest* and the other for certifying the signer's public key. [ECDSA-384][nist.fips.186-5] with SHA-384 is the recommended signature algorithm for signing manifests. And the *CA* should use a signature algorithm no weaker than the former.

## Measurements

### Introduction to RTMR

*RTMR* (**R**un**T**ime **M**easurement **R**egister) is a distinct feature of TDX. Generally, an *RTMR* behaves very similarly to a *PCR* in a TPM, that it cannot be set/assigned directly but can only be *extend*ed - i.e., new value of an *RTMR* is the cryptographic digest of the concatenation of its current value with the one supplied as a parameter to the *extend* operation.

### Measurement Log

The purpose of *RTMR*s is to authenticate *Measurement Log*s.

A *Measurement Log* is an ordered list of *Measurement Record*s maintained by software. Each *Measurement Record* corresponds to one value that was extended to an *RTMR*. Therefore, with the knowledge of the initial and final values of an *RTMR*, an (software) entity can verify the integrity of its *Measurement Log* using the following steps.

1. Initialize a 384-bit variable `H` to the initial value of the *RTMR*.
2. Iterate through the *Measurement Record*s in the *Measurement Log*.
   1. For each *Record*, derive `V` (from this *Record*, usually by hashing) to be the value that would be extended to the *RTMR*.
   2. Simulate the extension operation by calculating `H = sha384(H ∥ V)`.
3. Compare `H` and the final value of the *RTMR* and if they are the same, the *Measurement Log* is verified (i.e., has **not** been tampered).

### Measuring ACON Images

Every *Image* loaded into an *aTD* must be measured before any *Container*s can be created/launched from it.

An *Image* (and its behavior) can be uniquely identified by the two artifacts below.

- *Manifest* of the *Image*.
- Signing certificate used to sign the *Manifest*.


The digests of above collectively identify an *Image*. `acond` uses the same hash algorithm for computing both digests, and represents the result in the form of `HASH/SIGNER/MANIFEST`, which is referred to as the *Image ID* of an *Image*. How to determine the hash algorithm for computing an *Image ID* is detailed in [Cryptographic Algorithm Selection](#sign-signerid).

While loading an *Image* into the *aTD*, `acond` extends the *Image ID*, among other things, into an *RTMR*. External objects (e.g., *FS layer*s) do not have to be measured explicitly as their (cryptographic) digests
are already included in the *Manifest*.

## Filesystem Layers

The design philosophy of ACON image follows OCI image - A *Container*'s root directory is composed from multiple directory layers merged by [`overlay`](https://docs.kernel.org/filesystems/overlayfs.html) (or similar, like `aufs`). Each directory layer is called a *Filesystem Layer* (or *FS layer* for short) and is packaged into an uncompressed *tarball* for easy storage, transportation and measurement.

*FS layer*s are content addressable - i.e., the file name of an *FS layer* is its digest. A *Manifest* contains the digests of *FS layer*s linking the *Manifest* to the file names of those *FS layer*s and consequently to their contents. As a result, a signature of the *Manifest* authenticates the contents of both the *Manifest* and all of the referenced *FS layer*s.

*FS layer*s are merged by `overlay`, hence their order (as appearing in `layers`) matters. ACON image adopts the same ordering as in the OCI image spec, that *FS layer*s are listed in lower-layer-first order - e.g., with `"layers": [ "A", "B", "C" ]`, `overlay` will be given `lowerdir=C:B:A` option when being mounted.

The snippet below contains the `layers` element from the example [*Manifest*](#manifest).

```json
  "layers": [
    "signer/sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/SomeSharedLayer:2",
    "sha256/e67648e77428fe38272e3ebe300cf16607e2b0f7cba5e197f741d4a941e0c386",
    "sha384/8bf8dbf9f3c6e29660adf60f0eff64e6f2d47bf789d848386e6d2a644d5cf047d2bc06778f88e74f917a2dae41f641b8"
  ],
```

The general form of referencing an *FS layer* is `HASH/FSLAYER`, where `HASH` is the name of the hash algorithm and `FSLAYER` is the *FS layer*'s digest under `HASH`. As shown in the above example,

- The first entry is the bottom layer and is an [*Alias*](#aliases), which has the general form of `signer/HASH/SIGNER/ALIAS`. *Alias*es allow an *Image* to "import" *FS layer*s from other *Image*s, and are detailed in the next section.
- The middle/second entry is atypical in that `sha256` is used instead of (the recommended) SHA-384, but ACON does support a variety of hashes and allow them to be mixed in a *Manifest*.
- The last/third entry is the top layer and is a typical *FS layer* reference that uses a SHA-384 hash.

*FS layer*s must be unpacked to directories before they can be merged by `overlay` filesystem. For simplicity, those directories can be named using the *tarball*s' digests, so that it's trivial to map an *FS layer*'s digest found in a *Manifest* to the directory containing its content.

An *FS layer* may be shared among multiple *Image*s (i.e., referenced by multiple *Manifest*s), whose *Monifest*s may not agree on the same `HASH` for hashing the *FS layer*. Therefore, it's desirable for the layer's directory to have multiple paths (corresponding to different `HASH/FSLAYER`s). ACON uses the simple approach of defining a *primary* hash algorithm for naming the actual directory of an *FS layer*, while all other digests (under other hash algorithms) are mapped to symlinks pointing to the actual directory. SHA-384 is the *primary* hash algorithm.

The directory tree structure below (output from `tree` command) demonstrates the idea. Note that only `sha384/bdafff17.../` is a directory, while `sha256/66043e13...` and `sha512/85feb5a0...` are both symlinks.

```
$ tree -L 2 -F
.
├── sha256/
│   └── 66043e13ba3a9b4d061d55d35a0f416aff6203ec2072a1872b090bc562aa9f41 -> ../sha384/bdafff1742994d1e898887c076579b1380708552195ce03c42d3094a97da67161c047594791f07322ab35dd67feb3f81/
├── sha384/
│   └── bdafff1742994d1e898887c076579b1380708552195ce03c42d3094a97da67161c047594791f07322ab35dd67feb3f81/
└── sha512/
    └── 85feb5a092d8ab3700979a23ef30dce92b0f5c09069843045f5edc39c601185e29a187e258ce845e7c40e1935120c2b14f9b4cd6e39c79c8644aed61fa49d568 -> ../sha384/bdafff1742994d1e898887c076579b1380708552195ce03c42d3094a97da67161c047594791f07322ab35dd67feb3f81/
```

**Note**: The path component `HASH` (i.e., `sha256`, `sha384`, and `sha512` in the example above) is intended to distinguish digests produced by different algorithms, and is necessary for security.

## Aliases

An *Alias* is a symbolic reference to an object. Two types of *Alias*es have been defined currently.

- *FS layer Alias*es.
- *Image Alias*es.

*FS layer Alias*es allow *Image* authors to delegate (some of) an *Image*'s *FS layer*s to their vendors. It is necessary to support use cases such as *FaaS* (*Function as a Service*), in which a *Container*'s directory tree usually contains the function code from the developer, the *FaaS* framework from the *CSP* (e.g., for handling/generating HTTP requests/responses), and the programming language runtime (e.g., interpreters, JIT compilers, standard libraries, etc.). It's desirable that the *CSP* can update the *Image* on behalf of the function developer when a new patch with security fixes is available for the programming language runtime. Without *FS layer Alias*es, that is not possible as any changes to a layer would change its cryptographic digest hence break the *Image*'s signature.

*Image Alias*es allow a [Launch Policy](#launch-policy) rule to match a spectrum of *Image*s from the same vendor. There are use cases where multiple *Image*s have to share (hence collaborate in) an *aTD*. It is necessary to allow individual *Image* to be updated independent of the others. A Launch Policy rule at a high level specifies the *Manifest* digest of an *Image* allowed to share an *aTD* with the policy bearer. Without *Image Alias*es, no changes to that *Image* would be allowed later on because otherwise its digest would change and the policy rule would be broken.

### Definition

An *Alias* is a symbolic reference to an object, and is defined by providing in an *Image*'s *Manifest* the association between the symbolic name with the cryptographic identity of the object being aliased.

If an object is a directory, such as an *FS layer* directory, its aliases could be conceptually considered to be (and practically implemented as) symlinks pointing back to it. The multi-digest example in the [Filesystem Layers](#filesystem-layers) section is indeed a special case of *Alias*es (defined by `acond` internally).

*Alias*es, once defined, can appear anywhere that same type of objects are accepted in *Manifest*s.

*Alias*es bear security risks, as they could potentially be defined by adversaries with the intention to bring malicious contents into *Image*s that reference them. Therefore, every *Alias* must be bound to the cryptographic identity of the entity that defines it. Given that all *Image*s are signed, the cryptographic identity can simply be the (digest of the) signing public key (or certificate). In practice, `acond` automatically prefixes every *Alias* by `signer/HASH/SIGNER/` when processing its definition in a *Manifest*.

**Note**: `HASH` must be the same hash algorithm as used in signing the certificate, and must be applied to the certificate in *DER* format to compute `SIGNER`. [Cryptographic Algorithm Selection](#cryptographic-algorithm-selection) details how to determine the hash algorithm.

The command below computes the SHA-384 digest of a certificate supplied in PEM format as a shell here-document.

```sh
openssl x509 -outform der << EOF | openssl dgst -sha384 -r
-----BEGIN CERTIFICATE-----
MIICUjCCAbSgAwIBAgIUJAjkbgUxkY3P9JT0tadLHAkJ6bcwCgYIKoZIzj0EAwMw
OzELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjEOMAwGA1UECgwFSW50ZWwx
CzAJBgNVBAsMAlMzMB4XDTIyMDEyMjAxMzgzN1oXDTIzMDEyMTAxMzgzN1owOzEL
MAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjEOMAwGA1UECgwFSW50ZWwxCzAJ
BgNVBAsMAlMzMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAhvqa03+K932juAjI
tOZ3exqsXtK0Xn9xeVWhOtWXKcDT0lLp3aQ7WHWClfV04E2Gy87p/AfKBib5lMQg
561jCH8B5EI9YHZkAIWNrbREX5riSsIwu1NYU7DLWblPHISlo4tbF4YwYbYXxyc5
S2EbiaXouzzC6Y8iUtp8MYyOKAErK46jUzBRMB0GA1UdDgQWBBQiF6Cce8pf4QY0
tcyKrkkOFPTj5zAfBgNVHSMEGDAWgBQiF6Cce8pf4QY0tcyKrkkOFPTj5zAPBgNV
HRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA4GLADCBhwJBTdlFTOLcYxbw9YnT0Jpd
O10m8PiSUqSrFEJUfngMygeSnR1RNVHf4lfPj0sGuRPjtXS2T8JPcwY53Fl83GNC
5v4CQgDDaG3ITSqeMOsFjLU+hzhDFFxnGtCeroayxzRhBHHkz2zKWQyEq32+47ms
cMKBvNft1M7aNhB87oxhP7YA73otiw==
-----END CERTIFICATE-----
EOF
```

The output should resemble

```
7be2e38d33d92874122df802ec3a3f3952bd38906f341f9fe456619447eeacc8272003e6b9434700f7bec7de2a8ade31 *stdin
```

If the certificate above were used to signed the example [*Manifest*](#manifest), the *Alias* `SharedLayerA:1` could be referenced by another *Image* (in `layers` of its *Manifest*) as below.

```
signer/sha384/7be2e38d33d92874122df802ec3a3f3952bd38906f341f9fe456619447eeacc8272003e6b9434700f7bec7de2a8ade31/SharedLayerA:1
```

And the *Alias* would be mapped (by `acond`) to the *FS layer* below.

```
sha256/e67648e77428fe38272e3ebe300cf16607e2b0f7cba5e197f741d4a941e0c386
```

### Types of Aliases

*Alias*es are typed, so that an *Alias* to an *FS layer* can never be misinterpreted as am *Image*, or vice versa.

Below lists all *Alias* types currently defined.

|Type      |Description
|----------|-----------
|`contents`|*Alias*es refer to objects in `acond`'s content store, such as *FS layer*s.
|`images` |**Reserved** for future use. No *Alias*es to *Image*s (except `self`, see below) are allowed to be defined currently.
|`self`    |*Alias*es refer to objects defined inside the current *Manifest* being processed. There's currently only **one** such object defined - `.`, which refers to the current *Image*. <br>**Note**: `.` is necessary as the digest of current *Manifest* is not known when it is being edited, hence cannot be referred to in the form of `HASH/MANIFEST`.

### Syntax

**TODO:** Convert below to JSON Schema.

The (informal) syntax for defining *Alias*es is

```
  "aliases": {
    "TYPE": {
      "OBJECT": [
          "ALIAS", ...
      ], ...
    }, ...
  }
```

Where,

- `TYPE` could be either `contents` or `self`. All *Alias*es of the same type must be grouped together.
- `OBJECT` could be one of
  - The object's digest, e.g., in the form of `HASH/FSLAYER` for *FS layer*s, allowed in `contents` only.
  - Another *Alias* of the same type, e.g., in the form of `signer/HASH/SIGNER/ALIAS` for *FS layer*s. This is allowed in `contents` only.
  - `.`. This is allowed in `self` only.
- `ALIAS` is a symbolic name to the enclosing `OBJECT`.
  - `ALIAS` must also be a valid Linux file name and must not contain slashes (`/`).
  - `ALIAS` cannot be `.` or `..`.
  - Multiple *Alias*es can be defined at the same time to the same enclosing `OBJECT`.

The excerpt below contains the `aliases` element from the example [*Manifest*](#manifest).

```json
  "aliases": {
    "contents": {
      "sha256/e67648e77428fe38272e3ebe300cf16607e2b0f7cba5e197f741d4a941e0c386": [
        "SharedLayerA:1",
        "SharedLayerA:0"
      ],
      "sha224/22dde86581f879abc2e77f1fff4a9da0654f846bc2744fe9ad361cb9": [
        "SharedLayerB:0"
      ],
      "signer/sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/SomeSharedLayer:2": [
        "SharedLayerC:2",
        "SharedLayerC:1",
        "SharedLayerC:0"
      ]
    },
    "self": {
      ".": [
        "SomeProduct:2",
        "SomeProduct:1",
        "SomeProduct:0"
      ]
    }
  },
```

In the example above,

- The `contents` group defines *FS layer Alias*es.
  - *Alias*es can be defined for *FS layer*s referenced by the current *Manifest*, e.g., `sha256/e67648e7...`.
  - *Alias*es can also be defined for *FS layer*s **not** referenced by the `layers` arrary - e.g., `sha224/22dde865...`.
  - *Alias*es can be defined for other *Alias*es - e.g., `signer/sha224/72a80257.../SomeSharedLayer:2`.
  - Multiple *Alias*es can be defined for an *FS layer* in one shot - e.g., `sha256/e67648e7...` has 2 *Alias*es, namely `SharedLayerA:1` and `SharedLayerA:0`.
    - It'd be good to have a naming convention that reflects both the content (e.g., its product name or description) and its *SVN* (*Secure Version Number*).
    - *Alias*es defined in the example are of the form `LAYER_NAME:SVN` - e.g., `ShareLayerA` is the layer's name/description, while `1` and `0` are its *SVN*s.
    - A newer version may be declared to be compatible with older versions by aliasing both the newer (e.g., `1` for `SharedLayerA`) and all older versions (e.g., `0` for `SharedLayerA`) to the same object. In the excerpt, the *FS layer* `sha256/e67648e7...` has 2 *Alias*es `SharedLayerA:1` and `SharedLayerA:0`, so will work with *Image*s requiring `SharedLayerA` at either *SVN* `0` or `1`, but **not** `2` or above.
- The `self` group defines *Image Alias*es to the current *Image*.
  - *Image Alias*es are used in *Launch Policy* evaluation.
  - Multiple *Image Alias*es can be defined for the current *Image* in one shot. In the excerpt, 3 *Alias*es have been defined for the current *Image*, namely `SomeProduct:2`, `SomeProduct:1`, and `SomeProduct:0`.

`acond` maps objects to directories (i.e., storing *FS layer*s and *Manifest*s in directories named using their digests) in a filesystem, and implements *Alias*es using symbolic links. E.g., *Alias*es defined in the example above would result in a directory tree that resembles the following (output from `tree` command).

```
.
│── images/
│   └── sha384/
│       └── 7be2e38d33d92874122df802ec3a3f3952bd38906f341f9fe456619447eeacc8272003e6b9434700f7bec7de2a8ade31/
│           ├── 89d3a2a87a796719a49212950a2c8df31402e2a3435446490169166c5044b0ef6f9c6f9fd93ea84dbd0c92ecf5730582/
│           │   └── acon-manifest.json
│           ├── SomeProduct:0 -> 89d3a2a87a796719a49212950a2c8df31402e2a3435446490169166c5044b0ef6f9c6f9fd93ea84dbd0c92ecf5730582/
│           ├── SomeProduct:1 -> 89d3a2a87a796719a49212950a2c8df31402e2a3435446490169166c5044b0ef6f9c6f9fd93ea84dbd0c92ecf5730582/
│           └── SomeProduct:2 -> 89d3a2a87a796719a49212950a2c8df31402e2a3435446490169166c5044b0ef6f9c6f9fd93ea84dbd0c92ecf5730582/
└── contents/
    └── signer/
        └── sha384/
            └── 7be2e38d33d92874122df802ec3a3f3952bd38906f341f9fe456619447eeacc8272003e6b9434700f7bec7de2a8ade31/
                ├── SharedLayerA:0 -> ../../../sha256/e67648e77428fe38272e3ebe300cf16607e2b0f7cba5e197f741d4a941e0c386/
                ├── SharedLayerA:1 -> ../../../sha256/e67648e77428fe38272e3ebe300cf16607e2b0f7cba5e197f741d4a941e0c386/
                ├── SharedLayerB:0 -> ../../../sha224/22dde86581f879abc2e77f1fff4a9da0654f846bc2744fe9ad361cb9/
                ├── SharedLayerC:0 -> ../../sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/SomeSharedLayer:2
                ├── SharedLayerC:1 -> ../../sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/SomeSharedLayer:2
                └── SharedLayerC:2 -> ../../sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/SomeSharedLayer:2
```

Things worth noting in the directory tree above:

- `images/sha384/7be2e38d.../89d3a2a8.../acon-manifest.json` corresponds to the example [*Manifest*](#manifest). The digest was computed by `jq -jcS . acon-manifest.json | openssl dgst -sha384`.
- `acon-manifest.json` is assumed to be signed by the example certificate in [Alias Definition](#definition) section. Both `contents/signer/sha384/7be2e38d...` and `images/sha384/7be2e38d...` were named using its digest.
- *Alias*es of the same type are grouped together and stored in the same directory - i.e.,
  - *FS layer*s `SharedLayer?:?` are located in `contents/signer/sha384/7be2e38d...`.
  - `SomeProduct:?` are located in `images/sha384/7be2e38d...`.
- *Alias*es may be defined prior to the aliased objects coming into existence - i.e., *Alias*es to non-existing objects will be dangling symlinks, but will become valid automatically once the directories they point to have been created.

## Launch Policy

### Consideration

ACON employs a per-*Image* policy model, in which each *Image* contains its own policy to explicitly accept other *Image*s to share an *aTD* with it. 2 *Image*s can shared an *aTD* if and only if their policies accept each other. Therefore, whether or not an additional *Image* can be accepted into an *aTD* is determined by the aggregated policy of all *Image*s that have been loaded so far into that *aTD*.

Contrasting to the per-*Image* policy model is the global policy model, in which a global policy is assciated with an *aTD* (usually at TD build time, e.g., by storing the digest of the policy in `MRCONFIGID` or `MROWNERCONFIG` of `TDCS`) to specify what *Image*s should/can be loaded into that *aTD*.

The per-*Image* policy model is in fact a superset of the global policy model, as any global policy that accepts a particular set of *Image*s is equivalent to specifying that same policy in any one *Image* of the set as a per-*Image* policy, and setting all other *Image*s' policies to "accept all".

### Definition

An *Image*'s *Launch Policy* determines what other *Image*s may share the same *aTD* with that *Image*. It is defined inside the *Manifest* by the JSON object `policy`, which contains the fields described in the following table.

|Field|Type|Description
|-|-|-
|`accepts`|*Array*|*Image*s that are allowed to share an *aTD* with the *Image* described in the *Manifest*.
|`rejectUnaccepted`|*Boolean*|`true` to reject all other *Image*s not listed in `accepts`, default `false`.

The fundamental idea of *Launch Policy* is whitelisting, and can be explained by the key points below.

- `accepts` specifies the whitelist, which usually contains the bearing *Image*'s immediate dependencies in practice.
- `accepts` is transitive - i.e., if *A* `accepts` *B* and *B* `accepts` *C*, then *A* accepts *C* regardless of whether *C* is on *A*'s `accepts` list or not.
- If *A* accepts both *B* and *C*, then *B* and *C* also accept each other unless `rejectUnaccepted` is `true` for *B* (or *C*), in which case *B* (or *C*) must accept *C* (or *B*) for them to coexist in the same *aTD*.

In graph theory terms, *Image*s and their *Launch Policies* comprise a directed graph, referred to as a *Policy Graph*, whose vertices are *Image*s and whose edges reflect `accepts` relationships - i.e., given *A* and *B* being 2 vertices on the graph, if *A* `accepts` *B*, then an edge exists going from *A* to *B*.

A *Policy Graph* may be valid or invalid. The criteria for a valid *Policy Graph* depend on whether there exist vertices with `rejectUnaccepted` set to `true`.

|Number of Vertices with `rejectUnaccepted == true`|Validity Requirements
|-|-
|`0` (None)|Any *Policy Graph* is valid.
|`1+`|All vertices (including those with `rejectUnaccepted == true`) must be reachable from **every** vertex with `rejectUnaccepted == true` - i.e., any spanning tree rooted at a vertex with `rejectUnaccepted == true` must cover all other vertices in the graph.

`acond` maintains a *Policy Graph* that reflects the set of loaded *Image*s and must be valid at any point in time. That is,

- `acond` initializes the *Policy Graph* empty as *aTD* starts with no *Image* loaded.
- When an *Image* is being loaded, `acond` creates a would-be graph, which is a copy of the current *Policy Graph* with new vertices and edges added according to the incoming *Image* and its *Launch Policy*. It then validates the would-be graph according to the criteria above, and if the would-be graph is
  - Valid - The incoming *Image* is accepted and the would-be graph becomes the current *Policy Graph*.
  - Invalid - The incoming *Image* is rejected and the current *Policy Graph* remains unchanged.

#### `accepts`

Below is an example `policy` to demonstrate the syntax of `accepts`. It is excerpted from the example [Manifest](#manifest).

```json
  "policy": {
    "accepts": [
      "sha256/c4c56a4bfe7a48ca831492c67cd68537ba46fd89876262f9a5ee5547466a94a8/ProductA:2",
      "sha256/c4c56a4bfe7a48ca831492c67cd68537ba46fd89876262f9a5ee5547466a94a8/ProductB:1",
      "sha224/72a802570f2a1759d33e8297f7cebf9c8fb947db8930143ff313b142/*",
      "sha384/*/4c1c3713b0c3d7fd36750e51f28c8f123dfcad9e506cbfd5d06432cdf2df4194327442571e805ca5b46c7ab151ead3cd"
    ],
    "rejectUnaccepted": true
  },
```

A policy rule has the general form of `HASH/SIGNER/MANIFEST`, where

- `HASH` is the hash algorithm - e.g., `sha384`.
- `SIGNER` is the digest of the signing certificate under `HASH`. This field accepts wildcard `*`.
- `MANIFEST` is either an *Alias* of the digest of the *Manifest* under `HASH`. This field accepts wildcard `*`.

The `accepts` field above contains 4 rules.

- The first 2 rules require exact match on all 3 components.
- The third rule matches all *Image*s signed by the certificate hashed to the specified digest regardless of the *Manifest*'s digest or *Alias*, as `MANIFEST` is a wildcard (`*`).
- In the last rule `MANIFEST` is a specific digest but `SIGNER` is a wildcard, thus the rule matches the exact *Manifest* hashed to the digest specified, regardless of the signing certificate.

#### `rejectUnaccepted`

`rejectUnaccepted` above is set to `true` to reject all *Image*s that are accepted neither directly (i.e., listed in `accepts` of this *Image*) nor indirectly (i.e., listed in `accepts` of an *Image* accepted directly/indirectly by this *Image*).

### Common Use Cases of Launch Policy

|Use Case|Intention|Policy
|-|-|-
|Dependency|There is one "main" *Image* that provides the desired functionality. Other *Image*s are brought in only when necessary.|Every *Image*'s `accepts` lists that *Image*'s immediate dependencies. `rejectUnaccepted` is set to `true` for the "main" *Image* (that interfaces external/untrusted entities) and `false` for all other *Image*s (supporting the "main" *Image*).
|Whitelist or Global Policy|The user specifies the exact set of *Image*s to be loaded in one *aTD*.|One *Image* has its `accepts` set to the whitelist and its `rejectUnaccepted` set to `true`; while all others have a nil/empty `policy`.
|Common Signer|The *aTD* can be shared by any *Image*s signed by the same certificate.|Every *Image*'s `accepts` contains only one rule to match specific signing certificate but arbitrary *Manifest*s (using `*`). `rejectUnaccepted` is set to `true` for all *Image*s.

## Execution Environment

*Container*s refer to processes created from executable image files in *Image*s' directory trees. There could be multiple *Container*s created from the same *Image*.

### Private Namespaces

*Container*s are isolated from each other by means of private [namespaces][man-namespaces.7] provided by the Linux kernel. The following namespaces are private to every *Container*.

- [User Namespace][man-user_namespaces.7]

  Every *Container* is started with UID `0` (`root`) in its own User namespace. This is usually referred to as "rootless container".

  Linux allows mapping of UIDs in a User namespace to UIDs in the initial User namespace. Only mapped UIDs can be used (i.e., made available through `setuid` family of syscalls) in a *Container*'s namespace. Only `0` is mapped by default, while additional UIDs must be specified in the `uids` field in an *Image*'s *Manifest*.

  In no cases *Container*s will share UIDs.

- [PID Namespace][man-pid_namespaces.7]

  The entry point (specified by the `entrypoint` field in an *Image*'s *Manifest*) is guaranteed to receive *PID* `1`. When the entry point exits, the kernel kills all processes automatically within this PID namespace, hence the whole *Container* will terminate as a result.

- [Mount Namespace][man-mount_namespaces.7]

  Every *Container* has its own root directory (like an OCI container), which is the result of a merge of all of its *FS layer*s using `overlay`. Besides, there are various *Container* specific pseudo-filesystems (e.g., `proc`) that need to be mounted for each *Container*. The dedicated mount namespace allows *Container*s to create/modify/remove its own mounts and also allows those mounts to be unmounted automatically upon *Container* termination.

- [IPC Namespace][man-ipc_namespaces.7]

  This isolates System V IPC objects and POSIX message queues.

If an *Image* supports restart (i.e., has `noRestart` unset or set to `false` in its *Manifest*), any *Container* launched from that *Image* will retain the same User (and UID/GID mappings) and Mount (and temporary files) namespaces across restarts. However, the PID and IPC namespaces will not be retained.

### Credentials

(The first process of) Every *Container* is started with a set of process identifiers - e.g., PID, Session ID, Process Group ID, UID, etc. They are referred to collectively as [credentials][man-credentials.7] in Linux.

**Note**: Multiple *Container*s may be launched from one *Image*, in which case each *Container* will still be executed with distinct credentials.

#### User and Group IDs

Every *Container*'s entry point is started with a distinct unprivileged UID and a GID that equals to its UID. That serves as a defense-in-depth measure to make sure every *Container* is "contained" - i.e., no *Container* has access to resources (e.g., processes, memory, files, etc.) owned by `acond` or any other *Container*, unless accesses are explicitly granted.

`acond` sets (by [`umask(2)`][man-umask.2]) *umask* to `0077` for all *Container*s, to prevent anyone other than the owner from accessing any newly created directories/files. A *Container* can grant other *Container*s accesses to any of its directories/files using [`chmod(2)`][man-chmod.2].

Given that UIDs and GIDs are just 32-bit integers on Linux (v2.4 and later), `acond` simply employs a monotonic counter to assign them sequentially.

**Note**: The *Overflow UID/GID* (default to `65534`, see `/proc/sys/kernel/overflowuid` in [`proc(5)`][man-proc.5] for details) must **not** be used by any *Container*s.

Given every *Container* has its own User namespace, its entry point is always started with the UID `0` that is mapped to the UID assigned to *Container* in the initial user namespace. An *Image* can request additional UIDs by listing those (additional non-zero UIDs) in `uids` in its *Manifest*.

`acond` allocates multiple (and potentially consecutive) UIDs to *Container*s requesting more than one UID, and map those UIDs by writing to `/proc/PID/uid_map`. Additionally, `acond` will also map the same set of GIDs by writing to `/proc/PID/gid_map` as well. Processes in those *Container*s can then switch to those UIDs/GIDs by calling [`setuid(2)`][man-setuid.2]/[`setgid(2)`][man-setgid.2] or [`seteuid(2)`/`seteguid(2)`][man-seteuid.2], or by executing (using [`execve(2)`][man-execve.2]) programs with set-user-ID/set-group-ID bits set.

**Note**: For set-user-ID/set-group-ID programs, if either of their user/group ID is not mapped (i.e., not listed in `uids`), their effective UID/GID would remain unchanged. Please see [user_namespaces(7)][man-user_namespaces.7] for details.

#### Session and Process Group IDs

Every *Container*'s entry point is started as the leader of both a new session and a new process group. That is, both its Session ID and Process Group ID are equal to its PID.

### Working Directory

A *Container*'s entry point is started in the directory specified by `workingDir` of the *Image*'s *Manifest*.

### Environment variables

Untrusted entities are allowed to specify environment variables in requests for starting *Container*s. Given the security risk, environment variables will be sanitized per `env` setting in the [*Manifest*](#manifest).

`env` is an ordered list of rules, each of which can be in one of the 3 forms below.

- `ENVVAR=VALUE` - The environment variable `ENVVAR` must be set and may be set to `VALUE`.
- `ENVVAR=` - This is a special case of the previous form, meaning `ENVVAR` may be *unset*.
- `ENVVAR` - The environment variable `ENVVAR` may be *unset* or set to any value.

The `env` rules are considered logical-OR'ed together - i.e., an environment variable setting is accepted if it matches any of the rules.

An environment variable may appear multiple times in `env`, in which case the first rule determines the default value if not set (i.e., absent in the *Container* start request from the untrusted entity).

**Note**: The general form of environment strings - `ENVVAR=VALUE`, is a **convention** not enforced by [`execve(2)`][man-execve.2]. That is, atypical environment strings like `"=no_name"`, `"no_value="`, `"no_equal_sign"` will all be accepted by [`execve(2)`][man-execve.2], but would seldom be accepted/used by applications. `acond` always considers `"=no_name"` invalid, while considers `"no_equal_sign"` valid only in a manifest (to allow any value), and interprets `"no_value="` as a request to unset an environment variable that has a default non-empty value.

Below we use examples to demonstrate how rules can be combined in various use cases.

**Example 1**: An environment variable must be set to a specific value.

```json
  "env": {
    "ABC=xyz"
  }
```

`ABC` appears only once and is assigned the value `xyz`, so

- If `ABC` is set in a *Container* start request, it must be set to `xyz`, or the request would be rejected by `acond`.
- If `ABC` is **not** set in a *Container* start request, it takes the default value `xyz`.

<p id="exenv-ex2"/>

**Example 2**: An environment variable must be set to one of the specified values, and default to the first value.

```json
  "env": {
    "ABC=xyz",
    "ABC=uvw",
  }
```

`ABC` is assigned 2 values - `xyz` and `uvw`, so

- If `ABC` is set in a *Container* start request, it must be set to either `xyz` or `uvw`, or the request would be rejected by `acond`.
- If `ABC` is **not** set in a *Container* start request, it takes the first assignment, which is `xyz`.

<p id="exenv-ex3"/>

**Example 3**: An environment variable must be *unset* or set to one of the specified values, and default to *unset*.
```json
  "env": {
    "ABC=",
    "ABC=xyz",
    "ABC=uvw",
  }
```

Here it is just a special case of [Example 2](#exenv-ex2),

- If `ABC` is set in a *Container* start request, it must be set to either `xyz` or `uvw`, or the request would be rejected by `acond`.
- If `ABC` is **not** set in a *Container* start request, it takes the the first assignment, which is *unset*.

<p id="exenv-ex4"/>

**Example 4**: An environment variable may be *unset* or set to any value, default to *unset*.
```json
  "env": {
    "HTTPS_PROXY"
  }
```

Given `HTTPS_PROXY` appears only once without an assignment,

- If `HTTPS_PROXY` is set in a *Container* start request, it is allowed to be any value.
- If `HTTPS_PROXY` is **not** set in a *Container* start request, it takes the first assignment, which doesn't exist, so it is left *unset*.

**Example 5**: An environment variable may be set to any value and default to a specific value.
```json
  "env": {
    "HTTPS_PROXY",
    "HTTPS_PROXY=http://proxy.example.com:80/"
  }
```

This example adds a default value to [Example 4](#exenv-ex4).

- If `HTTPS_PROXY` is set in a *Container* start request, it is allowed to be any value.
- If `HTTPS_PROXY` is **not** set in a *Container* start request, it takes the first assignment, which is `http://proxy.example.com:80/`.

**Example 6**: An environment variable must be *unset* or set to one of the specified values, and default to non-empty value.

```json
  "env": {
    "ABC=xyz",
    "ABC=uvw",
    "ABC=",
  }
```

This is the same as [Example 3](#exenv-ex3) except the first rule has been moved to the last.

- If `ABC` is set in a *Container* start request, it must be set to either `xyz` or `uvw`, or the request would be rejected by `acond`.
- If `ABC` is **not** set in a *Container* start request, it takes the the first assignment, which is `zyx`.
- If `ABC=` is passed in, it is unset (i.e., removed from the environment array).

### Directory Hierarchy

Each *Container* has its own mount namespace and root directory. And that is true even for *Container*s created from the same *Image*.

The table below summarizes the directories and files that exist in every *Container*'s directory hierarchy.

**Note**: UIDs/GIDs in the table below are given in the ***Container*'s User namespace**, in which `0` (i.e., `root`) is mapped to the *Container*'s UID in the **initial User namespace**. Any unmapped UIDs/GIDs are given the *Overflow UID/GID*, which are `65534` by default and configurable by writing to `/proc/sys/kernel/overflowuid` and `/proc/sys/kernel/overflowgid`.

|Path|UID:GID|Mode|Filesystem|Notes
|-|-|-|-|-
|`/`|`0`:`0`|`drwxr-xr-x`|`overlay`|`/` is by default read-only (i.e., **no** `upperdir=` option is specified when mounting the `overlay`) to *Container*s unless `writableFS` is `true`.
|`/dev`|`nobody`:`nogroup`|`drwxr-xr-x`|`devtmpfs` *Bind Mount*|Mounted (by `acond`) once at `/dev` in the root mount namespace, then bind-mounted recursively (i.e., by to `MS_REC`, see [`mount(2)`][man-mount.2] for details) to `/dev` in every *Container*'s directory tree.
|`/dev/pts`|`nobody`:`nogroup`|`drwxr-xr-x`|`devpts` *Bind Mount*|Mounted once at `/dev/pts` in the root mount namespace, then bind-mounted recursively/implicitly along with `/dev`.
|`/proc`|`nobody`:`nogroup`|`dr-xr-xr-x`|`proc`|Each *Container* has its own PID namespace and `proc` mount.
|`/tmp`|`0`:`0`|`drwxrwxrwt`|`tmpfs`|Writable temporary storage with permissions set per Linux convention.
|`/run`|`0`:`0`|`drwxr-xr-x`|`tmpfs`|Same as `/tmp`, except its owner/group IDs and mode. <br>**Note**: It could be a symlink pointing to `/tmp/run/`.
|`/run/user/*`|`N`:`N`|`drwx------`||There should be one directory for UID `0`, and for every UID listed in `uids`. Each directory shall be owned by the UID and named using the UID value - e.g., `/run/user/100` is owned by (and accessible only to) UID `100`.
|`/shared`|`nobody`:`nogroup`|`drwxrwxrwt`|`tmpfs` *Bind Mount*|Mounted by `acond`, this directory is bind-mounted to every *Container*'s directory tree for inter-*Container* communication. Everything here will be visible to all other *Container*s. Directories/files here will be deleted at termination of the owning *Container* if `noRestart` is `true` in its *Manifest*.
|`/lib/acon/entrypoint.d/*`|`0`:`0`|`-rwxr-xr-x`||These are additional [entry points](#entrypoints) of this *Image*.

**Note**: `/tmp` and `/run` are 2 `tmpfs` mounts writable by the *Container* regardless of `writableFS`. They don't differ in anyway from functional perspective, but are both provided for compliance with [Linux Filesystem Hierarchy Standard][linux-fhs].

### Additional Entry Points

Each *Image*'s main entry point is specified by `entrypoint` its *Manifest*.

Each *Image* may expose a set of additional *entry point*s to the outside world via `acond`'s gRPC interface `invoke()`. Each *entry point* is identified using the name of the executable file in the *Image*'s `/lib/acon/entrypoint.d/` directory.

There are two types of entry points - *standard* and *custom*.

- All *standard* entry points start with a **lowercase** letter. `acond` understands their semantics and invokes them for specific tasks. <br>**Note**: There's no *standard* entry point defined so far.
- All *custom* entry points start with an **UPPERCASE** letter. `acond` exposes them to untrusted code through its `Exec()` interface (e.g., `aconcli EXE PARAM...` calls `acond.Exec("EXE", PARAM...)`, which executes `/lib/acon/entrypoint.d/EXE PARAM...` in the specified *Container*).

**Note**: Though `acond` doesn't understand the semantics of *custom* entry points, the `aconcli` may. For instance, `aconcli` may support a `stop` subcommand that is built upon `/lib/acon/entrypoint.d/Kill`.

Environment variables passed to additional entry points are **not** constrained by `env` - i.e., `acond` does **not** sanitize environment variables according to the `evn` array in the *Manifest*, hence an additional entry point must sanitize all environment variables that affect its security.

Additional entry points are always started in `/` regardless of `workingDir` setting in the *Manifest*.

[oci-image-spec]: https://github.com/opencontainers/image-spec/blob/main/spec.md
[man-execve.2]: https://man7.org/linux/man-pages/man2/execve.2.html
[man-setuid.2]: https://man7.org/linux/man-pages/man2/setuid.2.html
[man-setgid.2]: https://man7.org/linux/man-pages/man2/setgid.2.html
[man-seteuid.2]: https://man7.org/linux/man-pages/man2/seteuid.2.html
[man-flock.2]: https://man7.org/linux/man-pages/man2/flock.2.html
[man-mount.2]: https://man7.org/linux/man-pages/man2/mount.2.html
[man-open.2]: https://man7.org/linux/man-pages/man2/open.2.html
[man-umask.2]: https://man7.org/linux/man-pages/man2/umask.2.html
[man-chmod.2]: https://man7.org/linux/man-pages/man2/chmod.2.html
[man-proc.5]: https://man7.org/linux/man-pages/man5/proc.5.html
[man-namespaces.7]: https://man7.org/linux/man-pages/man7/namespaces.7.html
[man-user_namespaces.7]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
[man-pid_namespaces.7]: https://man7.org/linux/man-pages/man7/pid_namespaces.7.html
[man-mount_namespaces.7]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
[man-ipc_namespaces.7]: https://man7.org/linux/man-pages/man7/ipc_namespaces.7.html
[man-credentials.7]: https://man7.org/linux/man-pages/man7/credentials.7.html
[linux-fhs]: https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.pdf
[jq-doc]: https://stedolan.github.io/jq/manual/
[nist.fips.186-5]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
[wiki-csr]: https://en.wikipedia.org/wiki/Certificate_signing_request
[wiki-eddsa]: https://en.wikipedia.org/wiki/EdDSA
[wiki-ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
[k8s-pods]: https://kubernetes.io/docs/concepts/workloads/pods/
