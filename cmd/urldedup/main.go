package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

type URLPattern struct {
	Regex    string
	Examples []string
}

func main() {
	fileFlag := flag.String("f", "", "Path to the file containing URLs")
	ignoreFlag := flag.String("ignore", "", "Comma-separated list of file extensions to ignore")
	flag.Parse()

	if *fileFlag == "" {
		fmt.Println("Please provide a file using -f")
		os.Exit(1)
	}

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

			maxExamples := 1
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

	for _, pattern := range patterns {
		// fmt.Println("Regex:", pattern.Regex)
		// fmt.Println("Examples:")
		for _, ex := range pattern.Examples {
			fmt.Println(ex)
		}
		// fmt.Println()
	}
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