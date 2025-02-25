# vt_subdomains

**vt_subdomains** is a Go application that queries the VirusTotal API to enumerate subdomains for a given domain. It handles paginated responses and automatically rotates between multiple API keys when a quota limit is reached.

## Features

- Enumerates subdomains for a target domain.
- Handles paginated responses using the VirusTotal `links.next` field.
- Rotates through multiple API keys (from environment variables) if a quota error (`QuotaExceededError`) occurs.
- Outputs a sorted, unique list of subdomains that match the target domain.

## Requirements

- Go (version 1.13 or later)
- A valid VirusTotal API key. You can provide multiple API keys via environment variables:
  - `VT_API_KEY`
  - `VT_API_KEY2` (optional)
  - `VT_API_KEY3` (optional)

## Installation

Clone the repository and build the application:

```bash
git clone https://github.com/gilsgil/vt_subdomains.git
cd vt_subdomains
go build -o vtsubdomains main.go

# OR

go install -v github.com/gilsgil/vtdomains@latest
```

## Usage 

Before running the application, ensure your VirusTotal API keys are set in your environment. For example, on Linux or macOS:

```
export VT_API_KEY="your_primary_api_key"
export VT_API_KEY2="your_secondary_api_key"
export VT_API_KEY3="your_tertiary_api_key"
```

Then run the application using the -d flag to specify the target domain:

```
./vt_subdomains -d example.com
```

Alternatively, you can run the application without building using go run:

```
VT_API_KEY="your_primary_api_key" VT_API_KEY2="your_secondary_api_key" VT_API_KEY3="your_tertiary_api_key" go run main.go -d example.com
```

## Environment Variables

The application expects the following environment variables to provide API keys:

```
VT_API_KEY: Your primary VirusTotal API key.
VT_API_KEY2: Your secondary VirusTotal API key (optional).
VT_API_KEY3: Your tertiary VirusTotal API key (optional).
```

If none of these variables are set, the application will exit with an error.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

```
You can copy this block directly into your `README.md` file without escaping issues. Adjust the repository URL and your username as needed.
```