// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/json"
	"strings"
	"crypto/sha512"
)

/**
 * The following contains a description of the Attestation token for SEV-SNP
 */

type OciSnpToken struct {
	Profile		string		`cbor:"90000,keyasint" json:"profile"`
	Evidence	OciSnpEvidence	`cbor:"89989,keyasint" json:"evidence"`
	ReferenceId	string		`cbor:"89988,keyasint" json:"reference-id"`
	TrustAnchorId	string		`cbor:"89987,keyasint" json:"trust-anchor-id"`
}

type OciSnpEvidence struct {
	Nonce			[]byte			`cbor:"89979,keyasint" json:"snp-nonce"`
	UniqueId		string			`cbor:"89978,keyasint" json:"snp-uniqueid"`
	Keys			OciSnpKeys		`cbor:"89977,keyasint" json:"snp-keys"`
	Core			OciSnpCoreComponents	`cbor:"89976,keyasint" json:"snp-core-components"`
	EvidenceTimestamp	string			`cbor:"89975,keyasint" json:"snp-evidence-timestamp"`
	SwInfo			OciSnpSwInfo		`cbor:"89974,keyasint" json:"snp-sw-info"`
	InstanceInfo		OciInstanceInfo		`cbor:"89972,keyasint" json:"snp-instance-info"`
}

type OciSnpKeys struct {
	Ark	string	`cbor:"89499,keyasint" json:"ark"`
	Ask	string	`cbor:"89498,keyasint" json:"ask"`
	Vcek	string	`cbor:"89497,keyasint" json:"vcek"`
}

type OciSnpCoreComponents struct {
	HwModel			string	`cbor:"89399,keyasint" json:"hw-model"`
	AttestationReport	[]byte	`cbor:"89398,keyasint" json:"attestation-report"`
	Vcpus			int	`cbor:"89397,keyasint" json:"vcpus"`
}

type OciSnpSwInfo struct {
	Kernel	string	`cbor:"89349,keyasint" json:"hw-model"`
}

type OciInstanceInfo struct {
	AvailabilityDomain	string		`cbor:"89199,keyasint" json:"availabilityDomain"`
	CanonicalRegionName	string		`cbor:"89198,keyasint" json:"canonicalRegionName"`
	CompartmentId		string		`cbor:"89197,keyasint" json:"compartmentId"`
	DefinedTags		OciDefinedTags	`cbor:"89196,keyasint" json:"definedTags"`
	DisplayName		string		`cbor:"89195,keyasint" json:"displayName"`
	FaultDomain		string		`cbor:"89194,keyasint" json:"faultDomain"`
	Hostname		string		`cbor:"89193,keyasint" json:"hostname"`
	Id			string		`cbor:"89192,keyasint" json:"id"`
	Image			string		`cbor:"89191,keyasint" json:"image"`
	Metadata		OciMetadata	`cbor:"89190,keyasint" json:"metadata"`
	OciAdName		string		`cbor:"89189,keyasint" json:"ociAdName"`
	Region			string		`cbor:"89188,keyasint" json:"region"`
	RegionInfo		OciRegionInfo	`cbor:"89187,keyasint" json:"regionInfo"`
	Shape			string		`cbor:"89186,keyasint" json:"shape"`
	ShapeConfig		OciShapeConfig	`cbor:"89185,keyasint" json:"shapeConfig"`
	State			string		`cbor:"89184,keyasint" json:"state"`
	TimeCreated		float64		`cbor:"89183,keyasint" json:"timeCreated"`
}

type OciDefinedTags struct {
	Operations		OciOperations			`cbor:"89129,keyasint" json:"Operations"`
	OracleRecommendedTags	OciOracleRecommendedTags	`cbor:"89128,keyasint" json:"Oracle-Recommended-Tags"`
	OracleTags		OciOracleTags			`cbor:"89127,keyasint" json:"Oracle-Tags"`
}

type OciOperations struct {
	CreateBy		string	`cbor:"89099,keyasint" json:"CreateBy"`
	CreatedDateTime		string	`cbor:"89098,keyasint" json:"CreatedDateTime"`
}

type OciOracleRecommendedTags struct {
	ResourceOwner		string	`cbor:"89089,keyasint" json:"ResourceOwner"`
	ResourceType		string	`cbor:"89088,keyasint" json:"ResourceType"`
}

type OciOracleTags struct {
	CreatedBy		string	`cbor:"89079,keyasint" json:"CreatedBy"`
	CreatedOn		string	`cbor:"89078,keyasint" json:"CreatedOn"`
}

type OciMetadata struct {
	SshAuthorizedKeys	string	`cbor:"89069,keyasint" json:"ssh_authorized_keys"`
}

type OciRegionInfo struct {
	RealmDomainComponent	string	`cbor:"89059,keyasint" json:"realmDomainComponent"`
	RealmKey		string	`cbor:"89058,keyasint" json:"realmKey"`
	RegionIdentifier	string	`cbor:"89057,keyasint" json:"regionIdentifier"`
	RegionKey		string	`cbor:"89056,keyasint" json:"regionKey"`
}

type OciShapeConfig struct {
	BaselineOcpuUtilization		string	`cbor:"89049,keyasint" json:"baselineOcpuUtilization"`
	MaxVnicAttachments		float64	`cbor:"89048,keyasint" json:"maxVnicAttachments"`
	MemoryInGBs			float64	`cbor:"89047,keyasint" json:"memoryInGBs"`
	NetworkingBandwidthInGbps	float64	`cbor:"89046,keyasint" json:"networkingBandwidthInGbps"`
	Ocpus				float64	`cbor:"89045,keyasint" json:"ocpus"`
}

func NewOciSnpToken(eat []byte) (Token, error) {
	ociToken := new(OciSnpToken)

	err := json.Unmarshal(eat, &ociToken)
	if err != nil {
		return nil, err
	}
	return ociToken, nil
}

func (t *OciSnpToken) VcpuCount() int {
	return t.Evidence.Core.Vcpus
}

func (t *OciSnpToken) GetNonce() []byte {
	return t.Evidence.Nonce
}

func (t *OciSnpToken) GetBytes() []byte {
	bytes, _ := json.Marshal(*t)

	return bytes
}

func (t *OciSnpToken) GetHwModel() string {
	return t.Evidence.Core.HwModel
}

func (t *OciSnpToken) GetAttestationReport() []byte {
	return t.Evidence.Core.AttestationReport
}

func scrubCertificate(cert string) string {
	cert_pieces := strings.Split(cert, "\\n")
	return strings.Join(cert_pieces, "\n")
}

func (t *OciSnpToken) GetArk() string {
	return scrubCertificate(t.Evidence.Keys.Ark)
}

func (t *OciSnpToken) GetAsk() string {
	return scrubCertificate(t.Evidence.Keys.Ask)
}

func (t *OciSnpToken) GetVcek() string {
	return scrubCertificate(t.Evidence.Keys.Vcek)
}

func (t *OciSnpToken) GetRefId() string {
	return t.ReferenceId
}

func (t *OciSnpToken) GetInstanceDigest() ([sha512.Size]byte, []byte) {
	instanceInfo, _:= json.Marshal(t.Evidence.InstanceInfo)
	return sha512.Sum512(instanceInfo), instanceInfo
}
