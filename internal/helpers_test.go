package pkg_test

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"io/ioutil"
	pkg "loldriverscan/internal"
	"os"
	"strings"
	"testing"

	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
)

func ioCopy(dst *strings.Builder, src *os.File) {
	buf := make([]byte, 1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}
func TestHeuristicNormalisePath(t *testing.T) {

	// Table test approach
	testCases := []struct {
		input        string
		expectedPath string
		expectedErr  error
	}{
		{
			input:        `system32\example.dll`,
			expectedPath: `C:\Windows\System32\example.dll`,
			expectedErr:  nil,
		},
		{
			input:        `systemRoot\file.txt`,
			expectedPath: `C:\Windows\file.txt`,
			expectedErr:  nil,
		},
		{
			input:        `??\some\path\file.txt`,
			expectedPath: `some\path\file.txt`,
			expectedErr:  nil,
		},
		// Error with Heuristic normalisation of path
		// {
		// 	input:        `system32\NonExistentFile.txt`,
		// 	expectedPath: "",
		// 	expectedErr:  fmt.Errorf("normalised path C:\\Windows\\system32\\NonExistentFile.txt does not exist: The system cannot find the file specified."),
		// },
	}

	patch := monkey.Patch(os.Stat, func(name string) (fs.FileInfo, error) {
		return nil, nil
	})
	defer patch.Unpatch()

	for _, test := range testCases {
		normalisedPath, err := pkg.HeuristicNormalisePath(test.input)
		if (err != nil && test.expectedErr == nil) || (err == nil && test.expectedErr != nil) || (err != nil && test.expectedErr != nil && err.Error() != test.expectedErr.Error()) {
			t.Errorf("Unexpected error: got %v, expected %v", err, test.expectedErr)
		}

		// Check if the normalized path matches the expected path
		if !strings.EqualFold(normalisedPath, test.expectedPath) {
			t.Errorf("Mismatched path: got %v, expected %v", normalisedPath, test.expectedPath)
		}

	}
}

func TestHashFile(t *testing.T) {
	t.Run("Test Hash for existing files", func(t *testing.T) {

		// Make a temporary file
		tmpFile, err := ioutil.TempFile("", "test_file.txt")
		if err != nil {
			t.Fatalf("Error creating temporary file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		// Write some content into it
		if _, err = tmpFile.WriteString("This is a test temp file"); err != nil {
			t.Fatalf("Error writing to temp file: %v", err)
		}

		defer tmpFile.Close()

		hash, err := pkg.HashFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("Unexpected error while hashing file: %v", err)
		}

		expectedMd5hash := fmt.Sprintf("%x", md5.Sum([]byte("This is a test temp file")))
		expectedSha1hash := fmt.Sprintf("%x", sha1.Sum([]byte("This is a test temp file")))
		expectedSha256hash := fmt.Sprintf("%x", sha256.Sum256(([]byte("This is a test temp file"))))

		if hash.Md5 != expectedMd5hash {
			t.Errorf("MD5 hash mismatch. Expected: %s, Got: %s", expectedMd5hash, hash.Md5)
		}
		if hash.Sha1 != expectedSha1hash {
			t.Errorf("SHA1 hash mismatch. Expected: %s, Got: %s", expectedSha1hash, hash.Sha1)
		}
		if hash.Sha256 != expectedSha256hash {
			t.Errorf("SHA256 hash mismatch. Expected: %s, Got: %s", expectedSha256hash, hash.Sha256)
		}
	})

	t.Run("Hashing non existing files", func(t *testing.T) {
		_, err := pkg.HashFile("testfile_2.txt")
		if err == nil {
			t.Error("Expected an error for non-existing file, but got nil.")
		}
	})
}

/*
 *	//  PE parser handling - Get Auth hash
 */

func TestPrintLolDrivers(t *testing.T) {

	// Test drivers
	drivers := []pkg.LolDriver{
		{
			Filename:  "Driver1.sys",
			Path:      "C:\\Windows\\System32\\drivers\\",
			Status:    "Loaded",
			Malicious: false,
			MD5:       "fcd6aa0a8c3f9dfc8efb5f49298a1109",
			ID:        "Driver1",
			CVEs:      []string{"CVE-2022-1234", "CVE-2022-5678"},
			Authentihash: pkg.Authentihash{
				Sha256: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			},
		},
		{
			Filename:  "MaliciousDriver.sys",
			Path:      "C:\\Malicious\\",
			Status:    "Loaded",
			Malicious: true,
			MD5:       "jcnruadbaguvixhesoyam",
			ID:        "MaliciousDriver",
			CVEs:      []string{"CVE-2023-1111"},
			Authentihash: pkg.Authentihash{
				Sha256: "efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678",
			},
		},
	}

	// Capturing STDOUT
	oldOutput := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Call the function being tested
	pkg.PrintLolDrivers(drivers)
	w.Close()
	os.Stdout = oldOutput

	// Read the output from the buffer
	var outputBuilder strings.Builder
	ioCopy(&outputBuilder, r)
	actualOutput := outputBuilder.String()

	for _, driver := range drivers {
		assert.Contains(t, actualOutput, driver.Filename)
		assert.Contains(t, actualOutput, driver.Path)
		assert.Contains(t, actualOutput, driver.MD5)
		assert.Contains(t, actualOutput, driver.ID)
		assert.Contains(t, actualOutput, "fcd6aa0a8c3f9dfc8efb5f49298a1109")
		assert.Contains(t, actualOutput, "jcnruadbaguvixhesoyam")

	}
}
