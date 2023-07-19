package pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	lolDriversApiUrl = `https://www.loldrivers.io/api/drivers.json`
)

type Authentihash struct {
	MD5    string `json:"SHA1"`
	Sha1   string `json:"MD5"`
	Sha256 string `json:"SHA256"`
}

type lolDriversApiResponse []struct {
	ID       string `json:"Id"`
	Category string `json:"Category"`
	Samples  []struct {
		Filename         string       `json:"Filename"`
		MD5              string       `json:"SHA1"`
		Sha1             string       `json:"MD5"`
		Sha256           string       `json:"SHA256"`
		OriginalFilename string       `json:"OriginalFilename"`
		Authentihash     Authentihash `json:"Authentihash"`
	} `json:"KnownVulnerableSamples"`
	Cve  []string `json:"CVE,omitempty"`
	CVEs []string `json:"CVEs,omitempty"`
}

type LolDriver struct {
	Filename     string       `json:"filename,omitempty"`
	Path         string       `json:"path,omitempty"`
	Status       string       `json:"status,omitempty"`
	Malicious    bool         `json:"malicious"`
	MD5          string       `json:"md5,omitempty"`
	Sha1         string       `json:"sha1,omitempty"`
	Sha256       string       `json:"sha256,omitempty"`
	ID           string       `json:"id,omitempty"`
	CVEs         []string     `json:"cves,omitempty"`
	Authentihash Authentihash `json:"authentihash"`
}

type lolDrivers struct {
	md5Map    map[string]string
	sha1Map   map[string]string
	sha256Map map[string]string

	authentihashMd5Map    map[string]string
	authentihashSha1Map   map[string]string
	authentihashSha256Map map[string]string

	lolDriverMap map[string]LolDriver
}

func (ld *lolDrivers) FindDriver(h Hashes, authentihashes Hashes) (LolDriver, error) {
	var id string
	var ok bool

	if id, ok = ld.authentihashMd5Map[authentihashes.Md5]; !ok {
		if id, ok = ld.authentihashSha1Map[authentihashes.Sha1]; !ok {
			if id, ok = ld.authentihashSha256Map[authentihashes.Sha256]; !ok {

				// iderify Direct Hashes
				if id, ok = ld.sha256Map[h.Sha256]; !ok {
					if id, ok = ld.sha1Map[h.Sha1]; !ok {
						if id, ok = ld.md5Map[h.Md5]; !ok {
							return LolDriver{}, fmt.Errorf("no matching driver")
						}
					}
				}

			}
		}
	}

	lolDriver := ld.lolDriverMap[id]

	lolDriver.MD5 = h.Md5
	lolDriver.Sha1 = h.Sha1
	lolDriver.Sha256 = h.Sha256

	lolDriver.Authentihash.MD5 = authentihashes.Md5
	lolDriver.Authentihash.Sha1 = authentihashes.Sha1
	lolDriver.Authentihash.Sha256 = authentihashes.Sha256

	return lolDriver, nil
}

func fetchApiNormaliseData() ([]LolDriver, error) {
	resp, err := http.Get(lolDriversApiUrl)
	if err != nil {
		return nil, fmt.Errorf("error downloading drivers list from %v: %v", lolDriversApiUrl, err)
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading json drivers data from response: %v", err)
	}

	apiResponse := lolDriversApiResponse{}
	if err := json.Unmarshal(data, &apiResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling api json data: %v", err)
	}

	driversList := []LolDriver{}

	for _, ld := range apiResponse {
		for _, s := range ld.Samples {
			data := LolDriver{
				ID:           ld.ID,
				MD5:          strings.ToLower(s.MD5),
				Sha1:         strings.ToLower(s.Sha1),
				Sha256:       strings.ToLower(s.Sha256),
				CVEs:         append(ld.CVEs, ld.Cve...),
				Filename:     s.Filename,
				Malicious:    ld.Category == "malicious",
				Authentihash: s.Authentihash,
			}

			if s.OriginalFilename != "" {
				data.Filename = s.OriginalFilename
			}

			driversList = append(driversList, data)
		}
	}
	return driversList, nil
}

func CreateVulnerableDriverFinder() (*lolDrivers, error) {
	driverData, err := fetchApiNormaliseData()
	if err != nil {
		return nil, err
	}

	drivers := &lolDrivers{
		md5Map:                make(map[string]string),
		sha1Map:               make(map[string]string),
		sha256Map:             make(map[string]string),
		authentihashMd5Map:    make(map[string]string),
		authentihashSha1Map:   make(map[string]string),
		authentihashSha256Map: make(map[string]string),
		lolDriverMap:          make(map[string]LolDriver),
	}

	for _, dd := range driverData {
		drivers.lolDriverMap[dd.ID] = dd

		if dd.Sha256 != "" {
			drivers.sha256Map[dd.Sha256] = dd.ID
		} else if dd.Sha1 != "" {
			drivers.sha1Map[dd.Sha1] = dd.ID
		} else if dd.MD5 != "" {
			drivers.md5Map[dd.MD5] = dd.ID
		}

		if dd.Authentihash.MD5 != "" {
			drivers.authentihashMd5Map[dd.Authentihash.MD5] = dd.ID
		} else if dd.Authentihash.Sha1 != "" {
			drivers.authentihashSha1Map[dd.Authentihash.Sha1] = dd.ID
		} else if dd.Authentihash.Sha256 != "" {
			drivers.authentihashSha256Map[dd.Authentihash.Sha256] = dd.ID
		}
	}

	return drivers, nil
}
