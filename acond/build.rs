// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile(&["proto/acon.proto"], &["proto"])?;

    Ok(())
}
