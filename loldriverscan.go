package main

import (
	"encoding/json"
	"flag"
	"fmt"
	pkg "loldriverscan/internal"
	"os"

	"golang.org/x/sys/windows/svc"
)

const (
	lolDriversIoDetailUrl = `https://www.loldrivers.io/drivers/`
	headerArt             = `
	 _           _ _____       _                _____                 
	| |         | |  __ \     (_)              / ____|                
	| |     ___ | | |  | |_ __ ___   _____ _ _| (___   ___ __ _ _ __  
	| |    / _ \| | |  | | '__| \ \ / / _ \ '__\___ \ / __/ _' | '_ \ 
	| |___| (_) | | |__| | |  | |\ V /  __/ |  ____) | (_| (_| | | | |
	|______\___/|_|_____/|_|  |_| \_/ \___|_| |_____/ \___\__,_|_| |_|

                                                           FourCore.io
 `
)

func main() {

	verbosePtr := flag.Bool("v", false, "Enable verbose mode")
	jsonOutputPtr := flag.String("json", "", "Use - for stdout or a filepath to save to the file")
	flag.Parse()

	verbose := *verbosePtr
	jsonOutput := *jsonOutputPtr

	if jsonOutput == "" {
		fmt.Println(headerArt)
	}

	svcMgr, err := pkg.ConnectToServiceManager()
	if err != nil {
		panic(err)
	}

	driverServices, err := pkg.ListDriverServices(svcMgr)
	if err != nil {
		panic(err)
	}

	lolDriversList, err := pkg.CreateVulnerableDriverFinder()
	if err != nil {
		panic(err)
	}

	loldrivers := []*pkg.LolDriver{}

	for _, svcName := range driverServices {
		dSvc, err := pkg.OpenService(svcMgr, svcName)
		if err != nil {
			if verbose {
				fmt.Printf("[-] Cannot open service %v: %v\n", svcName, err)
			}
			continue
		}

		svcConf, err := dSvc.Config()
		if err != nil {
			if verbose {
				fmt.Printf("[-] Cannot fetch service config for %v: %v\n", svcName, err)
			}
			continue
		}

		if svcConf.BinaryPathName == "" {
			if verbose {
				fmt.Printf("[-] No service binary present for %v\n", svcName)
			}
			continue
		}

		normalisedDriverPath, err := pkg.HeuristicNormalisePath(svcConf.BinaryPathName)
		if err != nil {
			if verbose {
				fmt.Printf("[-] Cannot normalize driver path for %v (Path: %v): %v\n", svcName, svcConf.BinaryPathName, err)
			}
			continue
		}

		hashes, err := pkg.HashFile(normalisedDriverPath)
		if err != nil {
			if verbose {
				fmt.Printf("[-] Cannot compute sha256 hash for %v: %v\n", normalisedDriverPath, err)
			}
			continue
		}
		driver := lolDriversList.FindDriver(hashes)
		if driver == nil {
			continue
		}
		driver.Path = normalisedDriverPath
		driver.ID = lolDriversIoDetailUrl + driver.ID

		if status, err := dSvc.Query(); err != nil {
			driver.Status = "Unknown"
		} else {
			switch status.State {
			case svc.Running:
				driver.Status = "Running"
			case svc.Stopped:
				driver.Status = "Stopped"
			case svc.Paused:
				driver.Status = "Paused"
			case svc.StartPending:
				driver.Status = "Start Pending"
			case svc.StopPending:
				driver.Status = "Stop Pending"
			default:
				driver.Status = "Unknown"
			}
		}

		loldrivers = append(loldrivers, driver)
	}

	if len(loldrivers) == 0 {
		fmt.Println("[+]No vulnerable drivers found")
	} else {
		if jsonOutput == "" {
			pkg.PrintLolDrivers(loldrivers)
		} else {
			jsonData, err := json.MarshalIndent(loldrivers, "", "    ")
			if err != nil {
				panic(fmt.Sprintf("cannot marshal json data: %v", err))
			}
			if jsonOutput == "-" {
				fmt.Println(string(jsonData))
			} else {
				if err := os.WriteFile(jsonOutput, jsonData, 0644); err != nil {
					panic(fmt.Sprintf("error writing to json file %v: %v", jsonOutput, err))
				}
			}
		}
	}

}
