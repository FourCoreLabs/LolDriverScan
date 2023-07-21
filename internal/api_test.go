package pkg_test

import (
	"fmt"
	pkg "loldriverscan/internal"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// For testing purposes
type testlolDrivers struct {
	md5Map    map[string]string
	sha1Map   map[string]string
	sha256Map map[string]string

	authentihashMd5Map    map[string]string
	authentihashSha1Map   map[string]string
	authentihashSha256Map map[string]string

	lolDriverMap map[string]pkg.LolDriver
}

// For testing purposes
func mockfectchNormaliseData() ([]pkg.LolDriver, error) {
	testdrivers := []pkg.LolDriver{
		{
			ID:           "driver-1",
			Filename:     "driver1.exe",
			Path:         "/sample/path/to/driver",
			Status:       "active",
			Malicious:    false,
			MD5:          "md5-hash",
			Sha1:         "sha1-hash",
			Sha256:       "sha256-hash",
			CVEs:         []string{"CVE-2021-1111", "CVE-2021-2222"},
			Authentihash: pkg.Authentihash{MD5: "auth-md5-1"},
		},
	}
	return testdrivers, nil

}

// For testing purposes
func (tes *testlolDrivers) mockFindDriver(h pkg.Hashes, auth pkg.Authentihash) (pkg.LolDriver, error) {
	id, ok := tes.authentihashMd5Map[auth.MD5]
	if !ok {
		id, ok = tes.authentihashSha1Map[auth.Sha1]
		if !ok {
			id, ok = tes.authentihashSha256Map[auth.Sha256]
			if !ok {
				// No matching driver found
				return pkg.LolDriver{}, fmt.Errorf("no matching driver")
			}
		}
	}

	// Found a matching driver ID, get the corresponding LolDriver object
	lolDriver := tes.lolDriverMap[id]

	// Update the fields of the LolDriver object with the provided hashes
	lolDriver.MD5 = h.Md5
	lolDriver.Sha1 = h.Sha1
	lolDriver.Sha256 = h.Sha256

	// Update the fields of the Authentihash object
	lolDriver.Authentihash.MD5 = auth.MD5
	lolDriver.Authentihash.Sha1 = auth.Sha1
	lolDriver.Authentihash.Sha256 = auth.Sha256

	// Return the updated LolDriver object
	return lolDriver, nil
}

func TestDrivers(t *testing.T) {
	lolDriversApiUrl := `https://www.loldrivers.io/api/drivers.json`

	// Check if the the response status returned is 200 OK
	res, err := http.Get(lolDriversApiUrl)
	if err != nil {
		t.Fatalf("Unable to make driver requestd: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code to be %v but got %v", http.StatusOK, res.StatusCode)
	}
}

func TestFetchApiNormaliseData(t *testing.T) {
	sampledriver, err := mockfectchNormaliseData() // Mocking HTTP Get request
	if err != nil {
		t.Fail() // Will not occur
	}

	assert.NotEmpty(t, sampledriver, "Driver list must not be empty")
	assert.Equal(t, sampledriver[0].ID, "driver-1")
}

func TestFindDriver(t *testing.T) {

	//For test
	testlolDrivers := testlolDrivers{
		authentihashMd5Map: map[string]string{
			"authMd5":     "testdriver-1",
			"authMD5hash": "testdriver-7",
		},
		authentihashSha1Map:   map[string]string{"authSha1": "testdriver-2"},
		authentihashSha256Map: map[string]string{"authSha256": "testdriver-3"},
		sha1Map:               map[string]string{"hashSha1": "testdriver-4"},
		sha256Map:             map[string]string{"hashSha256": "testdriver-5"},
		md5Map:                map[string]string{"hashMd5": "testdriver-6"},
		lolDriverMap: map[string]pkg.LolDriver{
			"testdriver-1": {ID: "testdriver-1", Authentihash: pkg.Authentihash{MD5: "authMD5hash"}},
			"testdriver-2": {ID: "testdriver-2", Authentihash: pkg.Authentihash{Sha1: "authSha1hash"}},
			"testdriver-3": {ID: "testdriver-3", Authentihash: pkg.Authentihash{Sha256: "authSha256"}},
			"testdriver-4": {ID: "testdriver-4"},
			"testdriver-5": {ID: "testdriver-5"},
			"testdriver-6": {ID: "testdriver-6"},
		},
	}

	// Case 1.1:
	t.Run("No matching drivers found [INVALID HASH]", func(t *testing.T) {
		_, err := testlolDrivers.mockFindDriver(pkg.Hashes{Md5: "testdriver-1"}, pkg.Authentihash{MD5: "authMD5HASH"})
		if err == nil {
			t.Errorf("Expected error, got nil error")
		}
	})

	// Case 1.2:
	t.Run("No matching drivers found [INVALID DRIVER]", func(t *testing.T) {
		_, err := testlolDrivers.mockFindDriver(pkg.Hashes{Md5: "testdriver-2"}, pkg.Authentihash{Sha256: "hashSha256"})
		if err == nil {
			t.Errorf("Expected error, got nil error")
		}
	})

	// Case 2:
	t.Run("Valid drivers found", func(t *testing.T) {
		foundDriver, err := testlolDrivers.mockFindDriver(pkg.Hashes{Md5: "testdriver-1"}, pkg.Authentihash{MD5: "authMd5"})
		if err != nil {
			t.Errorf("Expected nil error, got error")
		}
		assert.Equal(t, foundDriver.Authentihash.MD5, "authMd5")
		assert.Equal(t, foundDriver.MD5, "testdriver-1")
	})

}

func TestCreateVulnerableDriverFinder(t *testing.T) {
	// Call the function
	drivers, err := pkg.CreateVulnerableDriverFinder()
	if err != nil {
		t.Error("Expected nil error, got error")
	}

	assert.NotEmpty(t, drivers, "Expected drivers to have values")
	assert.NotNil(t, drivers, "Expected drivers to not be nil")
}
