package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
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

// URLPattern represents a regex pattern along with example URLs.
type URLPattern struct {
	Regex    string
	Examples []string
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

// httpClient is shared among all validations.
var httpClient *http.Client

func main() {
	// Define flags.
	fileFlag := flag.String("f", "", "Path to the file containing URLs")
	ignoreFlag := flag.String("ignore", "", "Comma-separated list of file extensions to ignore")
	verboseFlag := flag.Bool("v", false, "Show verbose output with regex patterns")
	examplesFlag := flag.Int("examples", 1, "Number of examples to show per pattern")
	burpGapFlag := flag.String("out-burp-gap", "BURP_GAP_URLs_with_params.txt", "Output file for URLs with suspicious parameters")
	burpFlag := flag.String("out-burp", "BURP_URLs_with_params.txt", "Output file for other URLs")
	threads := flag.Int("t", 10, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 10*time.Second, "HTTP request timeout")
	validateFlag := flag.Bool("validate", true, "Perform HTTP URL validation (default true)")
	flag.Parse()

	if *fileFlag == "" {
		fmt.Println("Please provide a file using -f")
		os.Exit(1)
	}

	// Setup logging.
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Setup output files.
	burpGapFile, err := os.Create(*burpGapFlag)
	if err != nil {
		log.Fatalf("Error creating BURP GAP file: %v", err)
	}
	defer burpGapFile.Close()

	burpFile, err := os.Create(*burpFlag)
	if err != nil {
		log.Fatalf("Error creating BURP file: %v", err)
	}
	defer burpFile.Close()

	// Process ignore extensions.
	ignoreExts := processIgnoreFlag(*ignoreFlag)

	// Read URLs from file.
	urls, err := readURLs(*fileFlag, ignoreExts)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Group URLs by path segment count.
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

	// Generate regex patterns from the URL groups.
	var patterns []URLPattern
	for _, group := range pathGroups {
		if len(group) == 0 {
			continue
		}
		groupPatterns := generateRegexPatterns(group, *examplesFlag)
		patterns = append(patterns, groupPatterns...)
	}

	// Gather all unique URLs from the pattern examples.
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

	// Setup the HTTP client with the specified timeout.
	httpClient = &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Validate URLs if the -validate flag is set; otherwise, assume all URLs are valid.
	validityResults := make(map[string]bool)
	if *validateFlag {
		validityResults = validateURLs(uniqueURLs, *threads, *timeout)
	} else {
		for _, u := range uniqueURLs {
			validityResults[u] = true
		}
	}

	// Process each pattern and write results based on suspicious parameters.
	processedURLs := make(map[string]bool)
	for _, pattern := range patterns {
		if *verboseFlag {
			fmt.Println("Regex:", pattern.Regex)
			fmt.Println("Examples:")
		}
		for _, ex := range pattern.Examples {
			// Deduplicate.
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
				continue // Skip invalid URLs.
			}

			// Check for suspicious parameters.
			if hasSuspiciousParams(parsed.Query()) {
				if _, err := burpGapFile.WriteString(ex + "\n"); err != nil {
					log.Printf("Failed to write to burp gap file for URL %s: %v", ex, err)
				}
				if *verboseFlag {
					fmt.Println("  SUS:", ex)
				}
			} else {
				if _, err := burpFile.WriteString(ex + "\n"); err != nil {
					log.Printf("Failed to write to burp file for URL %s: %v", ex, err)
				}
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

// generateRegexPatterns creates unique regex patterns for a group of URL info.
// It ensures that the same regex (pattern) is output only once, and if multiple
// URLs produce the same pattern, their examples are merged (with duplicates removed).
func generateRegexPatterns(group []urlInfo, examplesFlag int) []URLPattern {
	segmentsCount := len(group[0].pathSegments)
	dynamicSegments := make([]bool, segmentsCount)

	// Determine which segments are dynamic.
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

	// Use a map to ensure uniqueness by regex.
	patternMap := make(map[string]*URLPattern)

	// Group by query keys (joined by "&").
	queryGroups := make(map[string][]string)
	for _, info := range group {
		queryKey := strings.Join(info.queryKeys, "&")
		queryGroups[queryKey] = append(queryGroups[queryKey], info.original)
	}

	for qKeys, examples := range queryGroups {
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

		// Remove duplicate examples.
		uniqueExamples := make([]string, 0)
		exampleSet := make(map[string]bool)
		for _, ex := range examples {
			if !exampleSet[ex] {
				uniqueExamples = append(uniqueExamples, ex)
				exampleSet[ex] = true
			}
		}

		// Limit the number of examples.
		maxExamples := examplesFlag
		if maxExamples < 1 {
			maxExamples = 1
		}
		if len(uniqueExamples) > maxExamples {
			uniqueExamples = uniqueExamples[:maxExamples]
		}

		// Merge examples if the same regex pattern exists.
		if existing, ok := patternMap[fullRegex]; ok {
			for _, ex := range uniqueExamples {
				if !contains(existing.Examples, ex) {
					existing.Examples = append(existing.Examples, ex)
				}
			}
		} else {
			patternMap[fullRegex] = &URLPattern{
				Regex:    fullRegex,
				Examples: uniqueExamples,
			}
		}
	}

	// Convert map to slice.
	patterns := make([]URLPattern, 0, len(patternMap))
	for _, p := range patternMap {
		patterns = append(patterns, *p)
	}
	return patterns
}

// contains checks if a slice of strings contains the given string.
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// isURLValidWithCtx checks if a URL returns 200 or 302 without following redirects, using the provided context.
func isURLValidWithCtx(ctx context.Context, urlStr string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound
}

// validateURLs concurrently validates URLs using the specified number of threads and timeout.
func validateURLs(urls []string, threadCount int, timeout time.Duration) map[string]bool {
	results := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	jobChan := make(chan string, len(urls))
	baseCtx := context.Background()

	// Launch worker goroutines.
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for urlStr := range jobChan {
				ctx, cancel := context.WithTimeout(baseCtx, timeout)
				valid := isURLValidWithCtx(ctx, urlStr)
				cancel()
				mu.Lock()
				results[urlStr] = valid
				mu.Unlock()
			}
		}()
	}

	// Enqueue jobs.
	for _, u := range urls {
		jobChan <- u
	}
	close(jobChan)
	wg.Wait()
	return results
}

// hasSuspiciousParams returns true if any query parameter matches a known suspicious parameter.
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

// initSusParams initializes a map of suspicious parameters.
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

// processIgnoreFlag processes the ignore flag and returns a set of file extensions to ignore.
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

// readURLs reads URLs from a file using a buffered scanner and filters out ignored extensions.
func readURLs(filename string, ignoreExts map[string]bool) ([]parsedURL, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []parsedURL
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" {
			continue
		}
		parsed, err := url.Parse(trimmed)
		if err != nil {
			// Skip invalid URLs.
			continue
		}
		cleanPath := strings.TrimSuffix(parsed.Path, "/")
		base := path.Base(cleanPath)
		ext := strings.ToLower(strings.TrimPrefix(path.Ext(base), "."))
		if ignoreExts[ext] {
			continue
		}
		urls = append(urls, parsedURL{original: trimmed, parsed: parsed})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

// splitPath splits a URL path into non-empty segments.
func splitPath(p string) []string {
	var segments []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}

// sortedQueryKeys returns the sorted keys of a URL query.
func sortedQueryKeys(query url.Values) []string {
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// regexpEscape escapes a string for use in a regular expression.
func regexpEscape(s string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(s), "/", `\/`)
}
