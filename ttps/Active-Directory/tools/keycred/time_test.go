package keycred_test

import (
	"testing"
	"time"

	"github.com/RedTeamPentesting/keycred"
)

func TestTimeConversion(t *testing.T) {
	t0 := time.Now().UTC()
	t1 := keycred.TimeFromFileTime(keycred.TimeAsFileTime(t0))

	t0 = t0.Truncate(time.Microsecond)
	t1 = t1.Truncate(time.Microsecond)

	if !t0.Equal(t1) {
		t.Errorf("time changed from %s to %s", t0, t1)
	}
}
