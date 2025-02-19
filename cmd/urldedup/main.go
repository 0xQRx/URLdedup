package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Suspicious parameter lists
var (
	SUS_CMDI          = []string{"execute", "dir", "daemon", "cli", "log", "cmd", "download", "ip", "upload"}
	SUS_DEBUG         = []string{"test", "reset", "config", "shell", "admin", "exec", "load", "cfg", "dbg", "edit", "root", "create", "access", "disable", "alter", "make", "grant", "adm", "toggle", "execute", "clone", "delete", "enable", "rename", "debug", "modify"}
	SUS_FILEINC       = []string{"root", "directory", "path", "style", "folder", "default-language", "url", "platform", "textdomain", "document", "template", "pg", "php_path", "doc", "type", "lang", "token", "name", "pdf", "file", "etc", "api", "app", "resource-type"}
	SUS_IDOR          = []string{"count", "key", "user", "id", "extended_data", "uid2", "group", "team_id", "data-id", "no", "username", "email", "account", "doc", "uuid", "profile", "number", "user_id", "edit", "report", "order"}
	SUS_OPENREDIRECT  = []string{"u", "redirect_uri", "failed", "r", "referer", "return_url", "redirect_url", "prejoin_data", "continue", "redir", "return_to", "origin", "redirect_to", "next"}
	SUS_SQLI          = []string{"process", "string", "id", "referer", "password", "pwd", "field", "view", "sleep", "column", "log", "token", "sel", "select", "sort", "from", "search", "update", "pub_group_id", "row", "results", "role", "table", "multi_layer_map_list", "order", "filter", "params", "user", "fetch", "limit", "keyword", "email", "query", "c", "name", "where", "number", "phone_number", "delete", "report"}
	SUS_SSRF          = []string{"sector_identifier_uri", "request_uris", "logo_uri", "jwks_uri", "start", "path", "domain", "source", "url", "site", "view", "template", "page", "show", "val", "dest", "metadata", "out", "feed", "navigation", "image_host", "uri", "next", "continue", "host", "window", "dir", "reference", "filename", "html", "to", "return", "open", "port", "stop", "validate", "resturl", "callback", "name", "data", "ip", "redirect"}
	SUS_SSTI          = []string{"preview", "activity", "id", "name", "content", "view", "template", "redirect"}
	SUS_XSS           = []string{"path", "admin", "class", "atb", "redirect_uri", "other", "utm_source", "currency", "dir", "title", "endpoint", "return_url", "users", "cookie", "state", "callback", "militarybranch", "e", "referer", "password", "author", "body", "status", "utm_campaign", "value", "text", "search", "flaw", "vote", "pathname", "params", "user", "t", "utm_medium", "q", "email", "what", "file", "data-original", "description", "subject", "action", "u", "nickname", "color", "language_id", "auth", "samlresponse", "return", "readyfunction", "where", "tags", "cvo_sid1", "target", "format", "back", "term", "r", "id", "url", "view", "username", "sequel", "type", "city", "src", "p", "label", "ctx", "style", "html", "ad_type", "s", "issues", "query", "c", "shop", "redirect"}
	SUS_MASSASSIGNMENT = []string{"user", "profile", "role", "settings", "data", "attributes", "post", "comment", "order", "product", "form_fields", "request"}
)

var susParams = initSusParams()

type URLPattern struct {
	Regex    string
	Examples []string
}

type URLResult struct {
	url    string
	status int
	valid  bool
}

func main() {
	// Define flags
	fileFlag := flag.String("f", "", "Path to the file containing URLs")
	ignoreFlag := flag.String("ignore", "", "Comma-separated list of file extensions to ignore")
	verboseFlag := flag.Bool("v", false, "Show verbose output with regex patterns")
	examplesFlag := flag.Int("examples", 1, "Number of examples to show per pattern")
	burpGapFlag := flag.String("out-burp-gap", "BURP_GAP_URLs_with_params.txt", "Output file for URLs with suspicious parameters")
	burpFlag := flag.String("out-burp", "BURP_URLs_with_params.txt", "Output file for other URLs")
	threads := flag.Int("t", 10, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 10*time.Second, "HTTP request timeout")
	flag.Parse()

	if *fileFlag == "" {
		fmt.Println("Please provide a file using -f")
		os.Exit(1)
	}

	// Setup output files
	burpGapFile, err := os.Create(*burpGapFlag)
	if err != nil {
		fmt.Printf("Error creating BURP GAP file: %v\n", err)
		os.Exit(1)
	}
	defer burpGapFile.Close()

	burpFile, err := os.Create(*burpFlag)
	if err != nil {
		fmt.Printf("Error creating BURP file: %v\n", err)
		os.Exit(1)
	}
	defer burpFile.Close()

	ignoreExts := processIgnoreFlag(*ignoreFlag)

	urls, err := readURLs(*fileFlag, ignoreExts)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	pathGroups := make(map[int][]urlInfo)

	for _, u := range urls {
		segments := splitPath(u.parsed.Path)
		pathLength := len(segments)
		queryKeys := sortedQueryKeys(u.parsed.Query())
		pathGroups[pathLength] = append(pathGroups[pathLength], urlInfo{
			original:     u.original,
			pathSegments: segments,
			queryKeys:    queryKeys,
		})
	}

	var patterns []URLPattern

	for pathLen, group := range pathGroups {
		if len(group) == 0 {
			continue
		}

		segmentsCount := pathLen
		dynamicSegments := make([]bool, segmentsCount)

		for i := 0; i < segmentsCount; i++ {
			firstVal := group[0].pathSegments[i]
			for _, info := range group {
				if info.pathSegments[i] != firstVal {
					dynamicSegments[i] = true
					break
				}
			}
		}

		pathPatternParts := make([]string, segmentsCount)
		for i := 0; i < segmentsCount; i++ {
			if dynamicSegments[i] {
				pathPatternParts[i] = `[^/]+`
			} else {
				pathPatternParts[i] = regexpEscape(group[0].pathSegments[i])
			}
		}

		pathPattern := "^/" + strings.Join(pathPatternParts, "/")

		queryGroups := make(map[string][]string)
		for _, info := range group {
			queryKey := strings.Join(info.queryKeys, "&")
			queryGroups[queryKey] = append(queryGroups[queryKey], info.original)
		}

		// Process queryGroups to remove subsets
		var qkList []string
		var qkSlices [][]string
		for qk := range queryGroups {
			qkList = append(qkList, qk)
			qkSlices = append(qkSlices, strings.Split(qk, "&"))
		}

		isRedundant := make([]bool, len(qkList))
		for i := 0; i < len(qkList); i++ {
			for j := 0; j < len(qkList); j++ {
				if i == j {
					continue
				}
				if isSubset(qkSlices[i], qkSlices[j]) {
					isRedundant[i] = true
					break
				}
			}
		}

		nonRedundantGroups := make(map[string][]string)
		for idx, qk := range qkList {
			if !isRedundant[idx] {
				nonRedundantGroups[qk] = queryGroups[qk]
			}
		}

		for qKeys, examples := range nonRedundantGroups {
			var queryPattern string
			if qKeys != "" {
				keys := strings.Split(qKeys, "&")
				queryParts := make([]string, len(keys))
				for i, k := range keys {
					queryParts[i] = regexpEscape(k) + `=([^&]*)`
				}
				queryPattern = `\?` + strings.Join(queryParts, "&")
			}

			fullRegex := pathPattern
			if queryPattern != "" {
				fullRegex += queryPattern
			}

			maxExamples := *examplesFlag
			if maxExamples < 1 {
				maxExamples = 1
			}
			if len(examples) < maxExamples {
				maxExamples = len(examples)
			}
			patternExamples := examples[:maxExamples]

			patterns = append(patterns, URLPattern{
				Regex:    fullRegex,
				Examples: patternExamples,
			})
		}
	}

	// Step 1: Gather all unique URLs from the pattern examples.
	uniqueURLsMap := make(map[string]bool)
	for _, pattern := range patterns {
		for _, ex := range pattern.Examples {
			uniqueURLsMap[ex] = true
		}
	}
	uniqueURLs := make([]string, 0, len(uniqueURLsMap))
	for urlStr := range uniqueURLsMap {
		uniqueURLs = append(uniqueURLs, urlStr)
	}

	// Step 2: Concurrently validate all unique URLs.
	validityResults := validateURLs(uniqueURLs, *threads, *timeout)

	// Step 3: Process each pattern and use the precomputed validity.
	processedURLs := make(map[string]bool)
	for _, pattern := range patterns {
		if *verboseFlag {
			fmt.Println("Regex:", pattern.Regex)
			fmt.Println("Examples:")
		}
		for _, ex := range pattern.Examples {
			// Deduplicate within the loop.
			if processedURLs[ex] {
				continue
			}
			processedURLs[ex] = true

			// Check precomputed validity.
			if valid, ok := validityResults[ex]; !ok || !valid {
				if *verboseFlag {
					fmt.Println("  INVALID:", ex)
				}
				continue
			}

			// Parse URL for further processing.
			parsed, err := url.Parse(ex)
			if err != nil {
				continue // Skip invalid URLs
			}

			// Check for suspicious parameters
			if hasSuspiciousParams(parsed.Query()) {
				burpGapFile.WriteString(ex + "\n")
				if *verboseFlag {
					fmt.Println("  SUS:", ex)
				}
			} else {
				burpFile.WriteString(ex + "\n")
				if *verboseFlag {
					fmt.Println("  OK:", ex)
				}
			}
		}
		if *verboseFlag {
			fmt.Println()
		}
	}
}

func isSubset(a, b []string) bool {
	setB := make(map[string]struct{})
	for _, k := range b {
		setB[k] = struct{}{}
	}
	for _, k := range a {
		if _, ok := setB[k]; !ok {
			return false
		}
	}
	return true
}

// isURLValid checks if a URL returns 200 or 302 without following redirects.
// It now accepts a timeout parameter.
func isURLValid(urlStr string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound
}

// validateURLs concurrently validates URLs using the specified number of threads and timeout.
func validateURLs(urls []string, threadCount int, timeout time.Duration) map[string]bool {
	type job struct {
		url string
		idx int
	}

	results := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	jobChan := make(chan job, len(urls))

	// Start workers
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobChan {
				valid := isURLValid(j.url, timeout)
				mu.Lock()
				results[j.url] = valid
				mu.Unlock()
			}
		}()
	}

	// Send jobs
	for idx, u := range urls {
		jobChan <- job{url: u, idx: idx}
	}
	close(jobChan)

	wg.Wait()
	return results
}

func hasSuspiciousParams(query url.Values) bool {
	for param := range query {
		if susParams[strings.ToLower(param)] {
			return true
		}
	}
	return false
}

func addParams(m map[string]bool, params []string) {
	for _, p := range params {
		m[strings.ToLower(p)] = true
	}
}

func initSusParams() map[string]bool {
	params := make(map[string]bool)
	addParams(params, SUS_CMDI)
	addParams(params, SUS_DEBUG)
	addParams(params, SUS_FILEINC)
	addParams(params, SUS_IDOR)
	addParams(params, SUS_OPENREDIRECT)
	addParams(params, SUS_SQLI)
	addParams(params, SUS_SSRF)
	addParams(params, SUS_SSTI)
	addParams(params, SUS_XSS)
	addParams(params, SUS_MASSASSIGNMENT)
	return params
}

func processIgnoreFlag(ignore string) map[string]bool {
	ignoreExts := make(map[string]bool)
	if ignore == "" {
		return ignoreExts
	}
	exts := strings.Split(ignore, ",")
	for _, ext := range exts {
		cleanExt := strings.TrimPrefix(strings.ToLower(ext), ".")
		if cleanExt != "" {
			ignoreExts[cleanExt] = true
		}
	}
	return ignoreExts
}

func readURLs(filename string, ignoreExts map[string]bool) ([]parsedURL, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var urls []parsedURL
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid URL %q: %v", trimmed, err)
		}

		// Enhanced file extension detection
		cleanPath := strings.TrimSuffix(parsed.Path, "/")
		base := path.Base(cleanPath)
		ext := path.Ext(base)
		if ext != "" {
			ext = strings.TrimPrefix(ext, ".")
		}
		ext = strings.ToLower(ext)

		if _, ok := ignoreExts[ext]; ok {
			continue
		}

		urls = append(urls, parsedURL{
			original: trimmed,
			parsed:   parsed,
		})
	}
	return urls, nil
}

func splitPath(path string) []string {
	var segments []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}

func sortedQueryKeys(query url.Values) []string {
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func regexpEscape(s string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(s), "/", `\/`)
}

type parsedURL struct {
	original string
	parsed   *url.URL
}

type urlInfo struct {
	original     string
	pathSegments []string
	queryKeys    []string
}
