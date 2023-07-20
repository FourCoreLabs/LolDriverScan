package pkg_test

import (
	"fmt"
	pkg "loldriverscan/internal"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testlolDrivers struct {
	md5Map    map[string]string
	sha1Map   map[string]string
	sha256Map map[string]string

	authentihashMd5Map    map[string]string
	authentihashSha1Map   map[string]string
	authentihashSha256Map map[string]string

	lolDriverMap map[string]pkg.LolDriver
}

type testDriverApi struct {
	ID       string
	Category string
	Samples  []struct {
		Filename         string
		MD5              string
		Sha1             string
		Sha256           string
		OriginalFilename string
		Authentihash     pkg.Authentihash
	}
	Cve  []string
	CVEs []string
}

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

func mockCreateVulnerableDriverFinder() (*testlolDrivers, error) {
	driverData, err := pkg.CreateVulnerableDriverFinder()
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

// func TestFetchApiNormaliseData(t *testing.T) {
// 	lolDriversApiUrl := `https://www.loldrivers.io/api/drivers.json`
// 	resp, err := http.Get(lolDriversApiUrl)
// 	if err != nil {
// 		t.Fatalf("[FATAL]Unable to get requested driver: %v", err)
// 	}
// 	defer resp.Body.Close()
// 	responseData, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		t.Fatalf("[FATAL]Unable to read data from response: %v", err)
// 	}

// 	apiResponse := testDriverApi{}
// 	err = json.Unmarshal(responseData, &apiResponse)
// 	if err != nil {
// 		t.Error("Error unmarshalling response")
// 	}

// }

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
			"testdriver-7": {ID: "testdriver-7", Authentihash: pkg.Authentihash{MD5: "authMd5"}},
		},
	}

	// Case 1:
	t.Run("No matching drivers found", func(t *testing.T) {
		_, err := testlolDrivers.mockFindDriver(pkg.Hashes{Md5: "testdriver-6"}, pkg.Authentihash{MD5: "authMD5hash"})
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
		assert.Contains(t, foundDriver.Authentihash.MD5, "authMd5")
		assert.Contains(t, foundDriver.MD5, "testdriver-1")
	})

	//Case 3:
	t.Run("Correct drivers found", func(t *testing.T) {
		foundDriver, err := testlolDrivers.mockFindDriver(pkg.Hashes{Md5: "testdriver-1"}, pkg.Authentihash{MD5: "authMD5hash"})
		fmt.Println(foundDriver)
		if err != nil {
			t.Errorf("Expected nil error, got error")
		}

	})
}

func TestCreateVulnerableDriverFinder(t *testing.T) {
	//
}
