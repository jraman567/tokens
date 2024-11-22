// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"fmt"
	"strings"
)

const SevSnpProfile = "http://amd.com/sevsnp"

type SnpToken struct {
	Profile           string `cbor:"90000,keyasint" json:"profile"`
	Vek               string `cbor:"90001,keyasint" json:"vek"`
	AttestationReport []byte `cbor:"90002,keyasint" json:"attestation-report"`
}

func (s *SnpToken) GetAttestationReport() []byte {
	return s.AttestationReport
}

func scrubCertificate(cert string) string {
	cert_pieces := strings.Split(cert, "\\n")
	return strings.Join(cert_pieces, "\n")
}

func (s *SnpToken) GetVek() string {
	return scrubCertificate(s.Vek)
}

func (s *SnpToken) Validate() error {
	if s.Profile == "" {
		return fmt.Errorf("Profile name is unset")
	}

	if s.Profile != SevSnpProfile {
		return fmt.Errorf("Incorrect profile name: Expecting %v, but got %v",
			SevSnpProfile, s.Profile)
	}

	if s.Vek == "" {
		return fmt.Errorf("VEK is missing from token")
	}

	if s.AttestationReport == nil {
		return fmt.Errorf("Attestation Report is missing from token")
	}

	return nil
}
