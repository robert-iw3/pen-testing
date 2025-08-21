package keycred

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	fileTimeSize                 = 8
	fileTimeUnixOffsetDifference = 116444736000000000
	fileTimeUnixIntervalFactor   = 100
)

// TimeAsFileTimeBytes expresses the input time as FILETIME buffer according to:
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
func TimeAsFileTimeBytes(t time.Time) []byte {
	fileTime := make([]byte, fileTimeSize)
	binary.LittleEndian.PutUint64(fileTime, TimeAsFileTime(t))

	return fileTime
}

func TimeAsFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}

	fileTime := uint64(t.UnixNano()) / fileTimeUnixIntervalFactor // 100 ns intervals
	fileTime += fileTimeUnixOffsetDifference                      // different offset

	return fileTime
}

// TimeFromFileTimeBytes parses a FILETIME buffer according to:
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
func TimeFromFileTimeBytes(fileTime []byte) (t time.Time, err error) {
	if len(fileTime) != fileTimeSize {
		return t, fmt.Errorf("invalid FILETIME buffer size: %d bytes instead of %d", len(fileTime), fileTimeSize)
	}

	return TimeFromFileTime(binary.LittleEndian.Uint64(fileTime)), nil
}

func TimeFromFileTime(fileTime uint64) time.Time {
	if fileTime == 0 {
		return time.Time{}
	}

	fileTime -= fileTimeUnixOffsetDifference
	fileTime *= fileTimeUnixIntervalFactor

	return time.Unix(0, int64(fileTime))
}
