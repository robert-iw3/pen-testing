package keycred

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// CustomKeyInformation represents the CUSTOM_KEY_INFORMATION structure
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf).
type CustomKeyInformation struct {
	Version              uint8
	Flags                CustomKeyInformationFlags
	VolType              CustomKeyInformationVolType
	SupportsNotification CustomKeyInformationSupportsNotification
	FekKeyVersion        uint8
	KeyStrength          CustomKeyInformationKeyStrengh
	Reserved             []byte
	ExtendedInfo         []*EncodedExtendedCKI

	// FullRepresentation is not present in the struct, it is only used to
	// distinguish between the two representations.
	FullRepresentation bool
}

// Bytes returns the binary representation of the CUSTOM_KEY_INFORMATION
// structure.
func (cki *CustomKeyInformation) Bytes() []byte {
	var buf bytes.Buffer

	_ = writeBinary(&buf, binary.LittleEndian, cki.Version, cki.Flags)

	if !cki.FullRepresentation {
		return buf.Bytes()
	}

	reserved := cki.Reserved
	if reserved == nil {
		reserved = make([]byte, 10)
	}

	_ = writeBinary(&buf, binary.LittleEndian, cki.VolType,
		cki.SupportsNotification, cki.FekKeyVersion, cki.KeyStrength, reserved)

	for _, ei := range cki.ExtendedInfo {
		_ = writeBinary(&buf, binary.LittleEndian, ei.Bytes())
	}

	return buf.Bytes()
}

// String returns a human readable string representation of the
// CUSTOM_KEY_INFORMATION structure.
func (cki *CustomKeyInformation) String() string {
	if cki == nil {
		return "<empty>"
	}

	var properties []string

	if cki.Version != 1 {
		properties = append(properties, fmt.Sprintf("Abnormal Version 0x%x", cki.Version))
	}

	if cki.Flags != 0 {
		properties = append(properties, cki.Flags.String())
	}

	switch {
	case !cki.FullRepresentation && len(properties) == 0:
		properties = append(properties, "<empty stub>")
	case cki.FullRepresentation:
		properties = append(properties, "Volume Type: "+cki.VolType.String())
		properties = append(properties, "Notifications: "+cki.SupportsNotification.String())

		if cki.FekKeyVersion > 1 {
			properties = append(properties, fmt.Sprintf("Abnormal FEK Key Version 0x%x", cki.FekKeyVersion))
		}

		properties = append(properties, "Key Strength: "+cki.KeyStrength.String())

		if len(cki.ExtendedInfo) > 0 {
			properties = append(properties, fmt.Sprintf("%d Extended Info Entries", len(cki.ExtendedInfo)))
		}
	}

	return strings.Join(properties, ", ")
}

// ParseCustomKeyInformation parses the CUSTOM_KEY_INFORMATION structure from
// bytes. If strict parsing is enabled, it returns an error if a version field
// with an unexpected value is encountered.
func ParseCustomKeyInformation(data []byte, strict bool) (*CustomKeyInformation, error) {
	consumer := newConsumer(data, binary.LittleEndian)

	kci := &CustomKeyInformation{
		Version: consumer.Uint8(),
		Flags:   CustomKeyInformationFlags(consumer.Uint8()),
	}

	if strict && kci.Version != 1 {
		return nil, fmt.Errorf("custom key information version is set to %d instead of 1", kci.Version)
	}

	if consumer.Remaining() == 0 {
		return kci, consumer.Error()
	}

	kci.VolType = CustomKeyInformationVolType(consumer.Uint8())
	kci.SupportsNotification = CustomKeyInformationSupportsNotification(consumer.Uint8())
	kci.FekKeyVersion = consumer.Uint8()
	kci.KeyStrength = CustomKeyInformationKeyStrengh(consumer.Uint8())
	kci.FullRepresentation = true

	// Entra ID: Microsoft does not follow their own docs and only adds 0 or 9
	// reserved bytes instead of 10
	nReservedBytes := 10
	if consumer.Remaining() == 9 || consumer.Remaining() == 0 {
		nReservedBytes = consumer.Remaining()
	}

	kci.Reserved = consumer.Bytes(nReservedBytes)

	for consumer.Remaining() > 0 {
		extendedInfo := &EncodedExtendedCKI{
			Version: consumer.Uint8(),
			Size:    consumer.Uint8(),
		}

		if strict && extendedInfo.Version != 0 {
			return nil, fmt.Errorf("extended custom key information is set to %d instead of 0", extendedInfo.Version)
		}

		extendedInfo.Data = consumer.Bytes(int(extendedInfo.Size))

		kci.ExtendedInfo = append(kci.ExtendedInfo, extendedInfo)
	}

	consumer.Bytes(consumer.Remaining())

	return kci, consumer.Error()
}

// EncodedExtendedCKI holds extended custom key information in a within a
// CustomKeyInformation
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b2c0cb9b-e49e-4907-9235-f9fd7eee8c13).
type EncodedExtendedCKI struct {
	Version uint8
	Size    uint8
	Data    []byte
}

// Bytes returns the byte representation of the EncodedExtendedCKI.
func (e *EncodedExtendedCKI) Bytes() []byte {
	return packBytes(binary.LittleEndian, e.Version, e.Size, e.Data)
}

type CustomKeyInformationFlags uint8

func (f CustomKeyInformationFlags) String() string {
	var flags []string

	if f&CustomKeyInformationFlagsAttestation > 0 {
		flags = append(flags, "Attestation")
	}

	if f&CustomKeyInformationFlagsMFANotUsed > 0 {
		flags = append(flags, "MFA Not Used")
	}

	remaining := f & ^(CustomKeyInformationFlagsAttestation | CustomKeyInformationFlagsMFANotUsed)
	if remaining != 0 {
		flags = append(flags, fmt.Sprintf("Unknown Flag 0x%x", uint8(remaining)))
	}

	return strings.Join(flags, " | ")
}

const (
	CustomKeyInformationFlagsAttestation CustomKeyInformationFlags = 0x01
	CustomKeyInformationFlagsMFANotUsed  CustomKeyInformationFlags = 0x02
)

type CustomKeyInformationVolType uint8

func (vt CustomKeyInformationVolType) String() string {
	switch vt {
	case VolTypeNone:
		return "Not Specified"
	case VolTypeOSV:
		return "OS Volume"
	case VolTypeFDV:
		return "Fixed Data Volume"
	case VolTypeRDV:
		return "Removable Data Volume"
	default:
		return fmt.Sprintf("Unknown Vol Type (0x%x)", int(vt))
	}
}

const (
	VolTypeNone CustomKeyInformationVolType = 0x00
	VolTypeOSV  CustomKeyInformationVolType = 0x01
	VolTypeFDV  CustomKeyInformationVolType = 0x02
	VolTypeRDV  CustomKeyInformationVolType = 0x03
)

type CustomKeyInformationSupportsNotification uint8

func (sn CustomKeyInformationSupportsNotification) String() string {
	switch sn {
	case SupportsNotificationNone:
		return "Not Supported"
	case SupportsNotificationSupported:
		return "Supported"
	default:
		return fmt.Sprintf("Unknown Notification Support (0x%x)", int(sn))
	}
}

const (
	SupportsNotificationNone      CustomKeyInformationSupportsNotification = 0x00
	SupportsNotificationSupported CustomKeyInformationSupportsNotification = 0x01
)

type CustomKeyInformationKeyStrengh uint8

func (s CustomKeyInformationKeyStrengh) String() string {
	switch s {
	case KeyStrengthUnknown:
		return "Unknown"
	case KeyStrengthWeak:
		return "Weak"
	case KeyStrengthNormal:
		return "Normal"
	default:
		return fmt.Sprintf("Unknown Key Strength (0x%x)", int(s))
	}
}

const (
	KeyStrengthUnknown CustomKeyInformationKeyStrengh = 0x00
	KeyStrengthWeak    CustomKeyInformationKeyStrengh = 0x01
	KeyStrengthNormal  CustomKeyInformationKeyStrengh = 0x02
)
