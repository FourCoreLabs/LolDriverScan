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

type lolDriversApiResponse []struct {
	ID       string `json:"Id"`
	Category string `json:"Category"`
	Samples  []struct {
		Filename         string `json:"Filename"`
		MD5              string `json:"SHA1"`
		Sha1             string `json:"MD5"`
		Sha256           string `json:"SHA256"`
		OriginalFilename string `json:"OriginalFilename"`
	} `json:"KnownVulnerableSamples"`
	Cve  []string `json:"CVE,omitempty"`
	CVEs []string `json:"CVEs,omitempty"`
}

type LolDriver struct {
	Filename  string   `json:"filename,omitempty"`
	Path      string   `json:"path,omitempty"`
	Status    string   `json:"status,omitempty"`
	Malicious bool     `json:"malicious"`
	MD5       string   `json:"md5,omitempty"`
	Sha1      string   `json:"sha1,omitempty"`
	Sha256    string   `json:"sha256,omitempty"`
	ID        string   `json:"id,omitempty"`
	CVEs      []string `json:"cves,omitempty"`
}

type lolDrivers struct {
	md5Map    map[string]*LolDriver
	sha1Map   map[string]*LolDriver
	sha256Map map[string]*LolDriver
}

func (ld *lolDrivers) FindDriver(h *Hashes) *LolDriver {
	md5V := ld.md5Map[h.Md5]
	sha1V := ld.sha1Map[h.Sha1]
	sha256V := ld.sha256Map[h.Sha256]

	if md5V != nil {
		md5V.MD5 = h.Md5
		md5V.Sha1 = h.Sha1
		md5V.Sha256 = h.Sha1
		return md5V
	} else if sha1V != nil {
		sha1V.MD5 = h.Md5
		sha1V.Sha1 = h.Sha1
		sha1V.Sha256 = h.Sha1
		return sha1V
	} else if sha256V != nil {
		sha256V.MD5 = h.Md5
		sha256V.Sha1 = h.Sha1
		sha256V.Sha256 = h.Sha1
		return sha256V
	}

	return nil
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
				ID:        ld.ID,
				MD5:       strings.ToLower(s.MD5),
				Sha1:      strings.ToLower(s.Sha1),
				Sha256:    strings.ToLower(s.Sha256),
				CVEs:      append(ld.CVEs, ld.Cve...),
				Filename:  s.Filename,
				Malicious: ld.Category == "malicious",
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
		md5Map:    make(map[string]*LolDriver),
		sha1Map:   make(map[string]*LolDriver),
		sha256Map: make(map[string]*LolDriver),
	}

	for _, dd := range driverData {
		if dd.Sha256 != "" {
			drivers.sha256Map[dd.Sha256] = &dd
		} else if dd.Sha1 != "" {
			drivers.sha1Map[dd.Sha1] = &dd
		} else if dd.MD5 != "" {
			drivers.md5Map[dd.MD5] = &dd
		}
	}

	return drivers, nil
}
