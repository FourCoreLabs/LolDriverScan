package pkg

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func HeuristicNormalisePath(path string) (string, error) {
	path = strings.Trim(path, `\`)

	splitted := strings.SplitN(path, `\`, 2)
	if len(splitted) != 2 {
		return "", fmt.Errorf("cannot determine path %v", path)
	}

	var normalisedPath string

	switch prefix := strings.ToLower(splitted[0]); prefix {
	case "system32":
		kf, err := windows.KnownFolderPath(windows.FOLDERID_System, windows.KF_FLAG_NO_ALIAS)
		if err != nil {
			return "", fmt.Errorf("cannot determine known folder %v: %v", prefix, err)
		}
		normalisedPath = filepath.Join(kf, splitted[1])
	case "systemroot":
		kf, err := windows.KnownFolderPath(windows.FOLDERID_Windows, windows.KF_FLAG_NO_ALIAS)
		if err != nil {
			return "", fmt.Errorf("cannot determine known folder %v: %v", prefix, err)
		}
		normalisedPath = filepath.Join(kf, splitted[1])
	case "??":
		normalisedPath = splitted[1]
	}

	if _, err := os.Stat(normalisedPath); err != nil {
		return "", fmt.Errorf("normalised path %v does not exist: %v", normalisedPath, err)
	}

	return normalisedPath, nil
}

type Hashes struct {
	Md5    string
	Sha1   string
	Sha256 string
}

func HashFile(path string) (*Hashes, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return &Hashes{
		Md5:    fmt.Sprintf("%x", md5.Sum(data)),
		Sha1:   fmt.Sprintf("%x", sha1.Sum(data)),
		Sha256: fmt.Sprintf("%x", sha256.Sum256(data)),
	}, nil
}

func PrintLolDrivers(drivers []*LolDriver) {
	maxFilenameLen := len("Filename")
	maxPathLen := len("Path")
	maxStatusLen := len("Status")
	maxMaliciousLen := len("Malicious")
	maxMD5Len := len("MD5")
	maxIDLen := len("ID")
	maxCVEsLen := len("CVEs")

	for _, driver := range drivers {
		if len(driver.Filename) > maxFilenameLen {
			maxFilenameLen = len(driver.Filename)
		}
		if len(driver.Path) > maxPathLen {
			maxPathLen = len(driver.Path)
		}
		if len(driver.Status) > maxStatusLen {
			maxStatusLen = len(driver.Status)
		}
		maliciousStr := fmt.Sprintf("%v", driver.Malicious)
		if len(maliciousStr) > maxMaliciousLen {
			maxMaliciousLen = len(maliciousStr)
		}
		if len(driver.MD5) > maxMD5Len {
			maxMD5Len = len(driver.MD5)
		}
		if len(driver.ID) > maxIDLen {
			maxIDLen = len(driver.ID)
		}
		cves := strings.Join(driver.CVEs, ", ")
		if len(cves) > maxCVEsLen {
			maxCVEsLen = len(cves)
		}
	}

	// Format and print each driver
	fmt.Printf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
		maxFilenameLen, "Filename",
		maxPathLen, "Path",
		maxStatusLen, "Status",
		maxMaliciousLen, "Malicious",
		maxMD5Len, "MD5",
		maxIDLen, "ID",
		maxCVEsLen, "CVEs",
	)
	fmt.Printf("%s  %s  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", maxFilenameLen),
		strings.Repeat("-", maxPathLen),
		strings.Repeat("-", maxStatusLen),
		strings.Repeat("-", maxMaliciousLen),
		strings.Repeat("-", maxMD5Len),
		strings.Repeat("-", maxIDLen),
		strings.Repeat("-", maxCVEsLen),
	)

	for _, driver := range drivers {
		maliciousStr := fmt.Sprintf("%v", driver.Malicious)
		cves := strings.Join(driver.CVEs, ", ")
		fmt.Printf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
			maxFilenameLen, driver.Filename,
			maxPathLen, driver.Path,
			maxStatusLen, driver.Status,
			maxMaliciousLen, maliciousStr,
			maxMD5Len, driver.MD5,
			maxIDLen, driver.ID,
			maxCVEsLen, cves,
		)
	}
}
