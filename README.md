# URLDedup

URLDedup is a command-line tool designed to process a list of URLs, identify patterns, validate URLs in parallel using multi-threading, and detect suspicious query parameters that could indicate security vulnerabilities. Tool is made to work with `waymore` tool output.

## Features
- Reads a file containing URLs and processes them.
- Identifies patterns in URLs and detects suspicious query parameters.
- Uses multi-threading to validate URLs efficiently.
- Allows filtering out specific file extensions.
- Saves results into separate output files for suspicious and non-suspicious URLs.

## Installation

```sh
go install github.com/0xQRx/URLDedup/cmd/urldedup@main
```

## Usage

Run the tool using the following syntax:

```sh
urldedup -f urls.txt [options]
```

### Command-line Flags

| Flag               | Description |
|--------------------|-------------|
| `-f <file>`       | Path to the file containing URLs (required). |
| `-ignore <ext>`   | Comma-separated list of file extensions to ignore. |
| `-v`              | Enable verbose output to show regex patterns and URLs being processed. |
| `-examples <n>`   | Number of example URLs to show per pattern. Default is `1`. |
| `-out-burp-gap <file>` | Output file for URLs with suspicious parameters (default: `BURP_GAP_URLs_with_params.txt`). |
| `-out-burp <file>` | Output file for all other URLs (default: `BURP_URLs_with_params.txt`). |
| `-t <threads>`    | Number of concurrent threads for validation (default: `10`). |
| `-timeout <sec>`  | Timeout for HTTP requests in seconds (default: `10s`). |

## Example Usage

```sh
urldedup -f urls.txt -t 20 -timeout 15s -ignore jpg,png,css,js

urldedup -f URLs_with_params.txt -ignore "css,js,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,otf,ico,webp,mp4" -examples 1
```

This command:
- Reads `urls.txt`
- Ignores URLs with `.jpg`, `.png`, `.css`, and `.js` extensions
- Runs with 20 threads for validation
- Sets an HTTP request timeout of 15 seconds


