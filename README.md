# LolDriverScan

LolDriverScan is a golang tool that allows users to discover vulnerable drivers on their system.
This tool fetches the loldriverscan.io list from their APIs and scans the system for any vulnerable drivers
This project is implemented in Go and does not require elevated privileges to run.

## Features

- Scans the system for vulnerable drivers
- Provides verbose output for detailed information
- Supports JSON output for easy integration with other tools
- No elevated privileges are required

## Installation

### Release

Download the latest auto-generated release binary from [GitHub Releases](https://github.com/FourCoreLabs/LolDriverScan/releases). 

### Build

1. Make sure you have Go installed on your system. If not, you can download and install it from the official [Go website](https://golang.org/dl/)

2. Clone the [LolDriverScan](https://github.com/FourCoreLabs/LolDriverScan) project repository:

   ```shell
   git clone https://github.com/FourCoreLabs/LolDriverScan.git
   ```

3. Change into the project directory:

   ```shell
   cd LolDriverScan
   ```

4. Build the project
   ```shell
   go build
   ```

## Usage
Run the loldriverscan binary with the following command-line arguments:

   ```shell
   .\loldriverscan.exe [-v] [--json <filepath>]
   ```

-v or --verbose: Enable verbose mode for detailed output.  
--json <filepath>: Specify a filepath to save the output in JSON format. Use - to output to stdout.

## Examples

* Run the tool with verbose mode enabled:
   ```shell
   .\loldriverscan.exe -v
   ```

* Run the tool and save the output in a JSON file:
   ```shell
   .\loldriverscan.exe -json .\drivers.json
   ```

* Run the tool and output the JSON result to stdout:
   ```shell
   .\loldriverscan.exe -json -
   ```

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
