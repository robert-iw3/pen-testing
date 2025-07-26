package netescape

import (
	"testing"
)

func TestToCsv(t *testing.T) {
	payloads := []string{
		"",
		" ",
		"           ",
		"           \t",
		"\t",
		"hello world",
		"asdasd asd asd asf saffsa asf asf as as g er treg er erg weefwqefawe fwef awef awef awef ewa fawefawe fawef wae",
		"drwxr-xr-x    - user 23 Jul 23:49 .git		drwxr-xr-x    - user 23 Jul 23:34 lists.rw-r--r-- 1.9k user 23 Jul 23:41 csv.go",
		"drwxr-xr-x    - user 23 Jul 23:49 .git		drwxr-xr-x    - user 23 Jul \n23:34 lists.rw-r--r-- 1.9k user 23 Jul 23:41 csv.go",
	}

	// Cause there is some randomness in this CSV thingy.
	iterations := 1000

	for ri := 0; ri < iterations; ri++ {

		for _, payload := range payloads {
			csvData, err := ToCsv(&payload)
			if err != nil {
				t.Log(err)
				t.FailNow()
			}

			fromCsv, err := FromCSV(&csvData)
			if err != nil {
				t.Log(err)
				t.FailNow()
			}

			if payload != fromCsv {
				t.Log("payload doesn't match:")
				t.Log(payload)
				t.Log(fromCsv)
				t.FailNow()
			}
		}

	}
}
