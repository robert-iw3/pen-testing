package keycred_test

import (
	"bytes"
	"testing"

	"github.com/RedTeamPentesting/keycred"
)

func TestStubCustomKeyInformation(t *testing.T) {
	t.Parallel()

	cki, err := keycred.ParseCustomKeyInformation([]byte{1, byte(keycred.CustomKeyInformationFlagsMFANotUsed)}, true)
	if err != nil {
		t.Fatalf("cannot parse stub custom key information: %v", err)
	}

	if cki.Version != 1 {
		t.Errorf("unexpected version: %d", cki.Version)
	}

	if cki.Flags != keycred.CustomKeyInformationFlagsMFANotUsed {
		t.Errorf("unexpected flags: %s", cki.Flags)
	}

	_, err = keycred.ParseCustomKeyInformation([]byte{2, 0}, false)
	if err != nil {
		t.Fatalf("cannot parse stub custom key information in lax mode with unexpected version: %v", err)
	}

	_, err = keycred.ParseCustomKeyInformation([]byte{2, 0}, true)
	if err == nil {
		t.Fatalf("parsing stub custom key information with unexpected version in strict mode did not fail")
	}
}

func TestCustomKeyInformation(t *testing.T) {
	t.Parallel()

	cki := keycred.CustomKeyInformation{
		Version:              1,
		Flags:                keycred.CustomKeyInformationFlagsAttestation | keycred.CustomKeyInformationFlagsMFANotUsed,
		VolType:              keycred.VolTypeOSV,
		SupportsNotification: keycred.SupportsNotificationSupported,
		FekKeyVersion:        0,
		KeyStrength:          keycred.KeyStrengthNormal,
		ExtendedInfo: []*keycred.EncodedExtendedCKI{
			{
				Version: 0,
				Size:    5,
				Data:    []byte{1, 2, 3, 4, 5},
			},
			{
				Version: 0,
				Size:    1,
				Data:    []byte{1},
			},
		},
		FullRepresentation: true,
	}

	parsed, err := keycred.ParseCustomKeyInformation(cki.Bytes(), true)
	if err != nil {
		t.Fatalf("cannot parse custom key information: %v", err)
	}

	if cki.Version != parsed.Version {
		t.Errorf("version mismatch: want=%v, got=%v", cki.Version, parsed.Version)
	}

	if cki.Flags != parsed.Flags {
		t.Errorf("flags mismatch: want=%v, got=%v", cki.Flags, parsed.Flags)
	}

	if cki.VolType != parsed.VolType {
		t.Errorf("voltype mismatch: want=%v, got=%v", cki.VolType, parsed.VolType)
	}

	if cki.SupportsNotification != parsed.SupportsNotification {
		t.Errorf("supportsnotifications mismatch: want=%v, got=%v", cki.SupportsNotification, parsed.SupportsNotification)
	}

	if cki.FekKeyVersion != parsed.FekKeyVersion {
		t.Errorf("fekkeyversion mismatch: want=%v, got=%v", cki.FekKeyVersion, parsed.FekKeyVersion)
	}

	if cki.KeyStrength != parsed.KeyStrength {
		t.Errorf("keystrength mismatch: want=%v, got=%v", cki.KeyStrength, parsed.KeyStrength)
	}

	if len(cki.ExtendedInfo) != len(parsed.ExtendedInfo) {
		t.Errorf("got %d extended info entries instead of %d", len(parsed.ExtendedInfo), len(cki.ExtendedInfo))
	} else {
		for i := 0; i < len(cki.ExtendedInfo); i++ {
			if !bytes.Equal(cki.ExtendedInfo[i].Bytes(), parsed.ExtendedInfo[i].Bytes()) {
				t.Errorf("mismatch of extended info at index %d", i)
			}
		}
	}
}

func TestCustomKeyInformationStrictParsing(t *testing.T) {
	t.Parallel()

	cki := keycred.CustomKeyInformation{
		Version:              3,
		Flags:                keycred.CustomKeyInformationFlagsAttestation | keycred.CustomKeyInformationFlagsMFANotUsed,
		VolType:              keycred.VolTypeOSV,
		SupportsNotification: keycred.SupportsNotificationSupported,
		FekKeyVersion:        0,
		KeyStrength:          keycred.KeyStrengthNormal,
		ExtendedInfo: []*keycred.EncodedExtendedCKI{
			{
				Version: 0,
				Size:    5,
				Data:    []byte{1, 2, 3, 4, 5},
			},
		},
		FullRepresentation: true,
	}

	_, err := keycred.ParseCustomKeyInformation(cki.Bytes(), false)
	if err != nil {
		t.Fatalf("cannot parse custom key information in lax mode: %v", err)
	}

	_, err = keycred.ParseCustomKeyInformation(cki.Bytes(), true)
	if err == nil {
		t.Fatalf("parsing custom key information with invalid version in strict mode did not fail")
	}

	cki.Version = 1

	_, err = keycred.ParseCustomKeyInformation(cki.Bytes(), true)
	if err != nil {
		t.Fatalf("fixing version did not make custom key information parsable in strict mode: %v", err)
	}

	cki.ExtendedInfo = append(cki.ExtendedInfo, &keycred.EncodedExtendedCKI{Version: 1, Size: 1, Data: []byte{0}})

	_, err = keycred.ParseCustomKeyInformation(cki.Bytes(), false)
	if err != nil {
		t.Fatalf("cannot parse custom key information in lax mode: %v", err)
	}

	_, err = keycred.ParseCustomKeyInformation(cki.Bytes(), true)
	if err == nil {
		t.Fatalf("parsing custom key information with invalid version in strict mode did not fail")
	}
}

func TestInvalidNumberOfReservedBytesFromEntra(t *testing.T) {
	t.Parallel()

	cki := keycred.CustomKeyInformation{
		Version:              1,
		Flags:                keycred.CustomKeyInformationFlagsAttestation | keycred.CustomKeyInformationFlagsMFANotUsed,
		VolType:              keycred.VolTypeOSV,
		SupportsNotification: keycred.SupportsNotificationSupported,
		FekKeyVersion:        0,
		KeyStrength:          keycred.KeyStrengthNormal,
		Reserved:             make([]byte, 9),
		FullRepresentation:   true,
	}

	_, err := keycred.ParseCustomKeyInformation(cki.Bytes(), true)
	if err != nil {
		t.Fatalf("cannot parse custom key information with 9 reserved bytes instead of 10: %v", err)
	}
}
