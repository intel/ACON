// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go_opt=Mproto/acon.proto="./" --go-grpc_out=. --go-grpc_opt=paths=source_relative --go-grpc_opt=Mproto/acon.proto="./" proto/acon.proto

package main
