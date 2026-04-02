package download

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var trackerSubscribeURLs = []string{
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_http.txt",
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_https.txt",
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt",
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt",
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ws.txt",
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt",
	"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best_ip.txt",
	"https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/all.txt",
	"https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/best.txt",
	"https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/http.txt",
}

var trackerBackupURLs = []string{
	"https://api.ttraw.com/trackers.txt",
}

const trackerCacheMaxAge = 24 * time.Hour

var trackerCacheMu sync.Mutex

type trackerCacheFile struct {
	UpdatedAt  time.Time `json:"updated_at"`
	RemoteURLs []string  `json:"remote_urls"`
	Trackers   []string  `json:"trackers"`
}

// Resolve trackers from cache first, then remote subscriptions, and only fall back to trackers.txt last.
func loadSubscribedTrackers() ([]string, error) {
	trackerCacheMu.Lock()
	defer trackerCacheMu.Unlock()

	cachePath, err := trackerCachePath()
	if err != nil {
		return nil, err
	}

	cache, cacheErr := readTrackerCache(cachePath)
	if cacheErr == nil && trackerCacheFresh(cache) {
		return cache.Trackers, nil
	}

	trackers, fetchErr := refreshSubscribedTrackers()
	if len(trackers) > 0 {
		cache = trackerCacheFile{
			UpdatedAt:  time.Now(),
			RemoteURLs: trackerRemoteURLs(),
			Trackers:   trackers,
		}
		if err := writeTrackerCache(cachePath, cache); err != nil {
			fmt.Println("warning: write tracker cache failed:", err)
		}
		return trackers, nil
	}

	if len(cache.Trackers) > 0 {
		return cache.Trackers, nil
	}

	localTrackers, localErr := readTrackerFile(trackerFallbackPath())
	if len(localTrackers) > 0 {
		return localTrackers, nil
	}

	if fetchErr != nil && localErr != nil {
		return nil, fmt.Errorf("refresh tracker subscriptions failed: %v; read fallback trackers.txt failed: %w", fetchErr, localErr)
	}
	if fetchErr != nil {
		return nil, fetchErr
	}
	if localErr != nil {
		return nil, localErr
	}
	return nil, fmt.Errorf("no trackers available from cache, remote URLs, or trackers.txt")
}

func trackerRemoteURLs() []string {
	remoteURLs := make([]string, 0, len(trackerSubscribeURLs)+len(trackerBackupURLs))
	remoteURLs = append(remoteURLs, trackerSubscribeURLs...)
	remoteURLs = append(remoteURLs, trackerBackupURLs...)
	return uniqueStrings(remoteURLs)
}

func trackerRuntimeDir() (string, error) {
	exePath, err := os.Executable()
	if err == nil && strings.TrimSpace(exePath) != "" {
		return filepath.Dir(exePath), nil
	}

	dir, err := filepath.Abs(".")
	if err != nil {
		return "", fmt.Errorf("resolve tracker runtime dir: %w", err)
	}
	return dir, nil
}

func trackerCachePath() (string, error) {
	runtimeDir, err := trackerRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(runtimeDir, "subscribed.json"), nil
}

func trackerFallbackPath() string {
	runtimeDir, err := trackerRuntimeDir()
	if err != nil {
		return ""
	}

	toolPath := filepath.Join(runtimeDir, "tools", "trackers.txt")
	if st, err := os.Stat(toolPath); err == nil && !st.IsDir() {
		return toolPath
	}

	return filepath.Join(runtimeDir, "trackers.txt")
}

func trackerCacheFresh(cache trackerCacheFile) bool {
	if len(cache.Trackers) == 0 {
		return false
	}
	if cache.UpdatedAt.IsZero() || time.Since(cache.UpdatedAt) > trackerCacheMaxAge {
		return false
	}
	return sameStringSet(cache.RemoteURLs, trackerRemoteURLs())
}

func readTrackerCache(path string) (trackerCacheFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return trackerCacheFile{}, err
	}

	var cache trackerCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return trackerCacheFile{}, fmt.Errorf("parse tracker cache: %w", err)
	}
	cache.RemoteURLs = uniqueStrings(cache.RemoteURLs)
	cache.Trackers = uniqueStrings(cache.Trackers)
	return cache, nil
}

func writeTrackerCache(path string, cache trackerCacheFile) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tracker cache: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write tracker cache temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace tracker cache: %w", err)
	}
	return nil
}

func refreshSubscribedTrackers() ([]string, error) {
	httpClient := &http.Client{Timeout: 8 * time.Second}

	trackers, subErr := fetchTrackerSubscriptions(httpClient, trackerSubscribeURLs)
	if len(trackers) > 0 {
		return trackers, nil
	}

	backupTrackers, backupErr := fetchTrackerURLs(httpClient, trackerBackupURLs)
	if len(backupTrackers) > 0 {
		return backupTrackers, nil
	}

	if subErr != nil && backupErr != nil {
		return nil, fmt.Errorf("subscription URLs failed: %v; backup URLs failed: %w", subErr, backupErr)
	}
	if subErr != nil {
		return nil, subErr
	}
	if backupErr != nil {
		return nil, backupErr
	}
	return nil, fmt.Errorf("no trackers returned by remote URLs")
}

func fetchTrackerSubscriptions(httpClient *http.Client, subscribeURLs []string) ([]string, error) {
	type result struct {
		trackers []string
		err      error
	}

	results := make(chan result, len(subscribeURLs))
	var wg sync.WaitGroup

	for _, subscribeURL := range subscribeURLs {
		subscribeURL := strings.TrimSpace(subscribeURL)
		if subscribeURL == "" {
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			trackers, err := fetchTrackerSubscription(httpClient, subscribeURL)
			results <- result{trackers: trackers, err: err}
		}()
	}

	wg.Wait()
	close(results)

	var (
		all      []string
		firstErr error
	)
	for res := range results {
		if len(res.trackers) > 0 {
			all = append(all, res.trackers...)
			continue
		}
		if firstErr == nil && res.err != nil {
			firstErr = res.err
		}
	}

	all = uniqueStrings(all)
	if len(all) > 0 {
		return all, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("no trackers returned by subscription URLs")
}

func fetchTrackerURLs(httpClient *http.Client, urls []string) ([]string, error) {
	var (
		all      []string
		firstErr error
	)

	for _, rawURL := range urls {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}

		trackers, err := fetchTrackersOne(httpClient, rawURL)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		all = append(all, trackers...)
	}

	all = uniqueStrings(all)
	if len(all) > 0 {
		return all, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("no trackers returned by backup URLs")
}

func fetchTrackerSubscription(httpClient *http.Client, subscribeURL string) ([]string, error) {
	var firstErr error

	for _, candidate := range trackerSubscribeMirrorURLs(subscribeURL) {
		trackers, err := fetchTrackersOne(httpClient, candidate)
		if err == nil && len(trackers) > 0 {
			return trackers, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		return nil, fmt.Errorf("fetch tracker subscription %s: %w", subscribeURL, firstErr)
	}
	return nil, fmt.Errorf("tracker subscription %s returned no trackers", subscribeURL)
}

func fetchTrackersOne(httpClient *http.Client, rawURL string) ([]string, error) {
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("GET %s failed: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned status %d", rawURL, resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	trackers := make([]string, 0, 128)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		trackers = append(trackers, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s failed: %w", rawURL, err)
	}

	trackers = uniqueStrings(trackers)
	if len(trackers) == 0 {
		return nil, fmt.Errorf("%s returned no trackers", rawURL)
	}
	return trackers, nil
}

// Try alternate GitHub raw mirrors before falling back to the original host only.
func trackerSubscribeMirrorURLs(subscribeURL string) []string {
	urls := make([]string, 0, 3)

	if mirror := githubSourceMirrorURL(subscribeURL); mirror != "" {
		urls = append(urls, mirror)
	}
	if mirror := githubProxyMirrorURL(subscribeURL); mirror != "" {
		urls = append(urls, mirror)
	}
	urls = append(urls, subscribeURL)

	return uniqueStrings(urls)
}

func githubSourceMirrorURL(rawURL string) string {
	const prefix = "https://raw.githubusercontent.com/"

	if !strings.HasPrefix(rawURL, prefix) {
		return ""
	}

	parts := strings.Split(strings.TrimPrefix(rawURL, prefix), "/")
	if len(parts) < 4 {
		return ""
	}
	if parts[2] != "main" && parts[2] != "master" {
		return ""
	}

	return fmt.Sprintf("https://fastly.jsdelivr.net/gh/%s/%s/%s", parts[0], parts[1], strings.Join(parts[3:], "/"))
}

func githubProxyMirrorURL(rawURL string) string {
	const prefix = "https://raw.githubusercontent.com/"
	if !strings.HasPrefix(rawURL, prefix) {
		return ""
	}
	return "https://fastgit.cc/" + rawURL
}

func readTrackerFile(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("fallback trackers.txt path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	trackers := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		trackers = append(trackers, line)
	}
	return uniqueStrings(trackers), nil
}

func sameStringSet(left, right []string) bool {
	left = uniqueStrings(left)
	right = uniqueStrings(right)
	if len(left) != len(right) {
		return false
	}

	set := make(map[string]struct{}, len(left))
	for _, item := range left {
		set[item] = struct{}{}
	}
	for _, item := range right {
		if _, ok := set[item]; !ok {
			return false
		}
	}
	return true
}
