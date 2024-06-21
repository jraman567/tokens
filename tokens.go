// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/json"
	"crypto/sha512"
	"fmt"
)

type Token interface {
	VcpuCount() int
	GetNonce() []byte
	GetBytes() []byte
	GetHwModel() string
	GetAttestationReport() []byte
	GetArk() string
	GetAsk() string
	GetVcek() string
	GetRefId() string
	GetInstanceDigest() ([sha512.Size]byte, []byte)
}

var supportedTokens = map[string]func([]byte) (Token, error){
	"oci-amd-snp": NewOciSnpToken,
}

func GetToken(buf []byte) (Token, error) {
	var header struct {
		Type string `json:"profile"`
	}

	err := json.Unmarshal(buf, &header)
	if err != nil {
		fmt.Printf("Measurement: Unmarshal error\n")
		return nil, err
	}

	if init, ok := supportedTokens[header.Type]; ok {
		return init(buf)
	}

	return nil, fmt.Errorf("unsupported token %s", header.Type)
}
