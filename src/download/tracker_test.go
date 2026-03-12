package download

import (
	"testing"
	"time"
)

func TestTrackerSubscribeMirrorURLs(t *testing.T) {
	rawURL := "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt"

	got := trackerSubscribeMirrorURLs(rawURL)
	want := []string{
		"https://fastly.jsdelivr.net/gh/ngosang/trackerslist/trackers_all.txt",
		"https://fastgit.cc/" + rawURL,
		rawURL,
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected mirror count: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected mirror at %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestTrackerCacheFresh(t *testing.T) {
	cache := trackerCacheFile{
		UpdatedAt:  time.Now().Add(-time.Hour),
		RemoteURLs: trackerRemoteURLs(),
		Trackers:   []string{"udp://tracker.example:80/announce"},
	}
	if !trackerCacheFresh(cache) {
		t.Fatal("expected cache to be fresh")
	}

	cache.UpdatedAt = time.Now().Add(-2 * trackerCacheMaxAge)
	if trackerCacheFresh(cache) {
		t.Fatal("expected cache to be stale")
	}
}
