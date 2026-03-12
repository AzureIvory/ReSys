package download

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	"github.com/rs/dnscache"
)

var (
	btClientMu sync.Mutex
	btClient   *torrent.Client
)

// Reuse one BT client so DHT state and listening sockets stay warm across downloads.
func getBTClient() (*torrent.Client, error) {
	btClientMu.Lock()
	defer btClientMu.Unlock()

	if btClient != nil {
		return btClient, nil
	}

	dataDir, err := btClientDataDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create BT client dir: %w", err)
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = dataDir
	cfg.Seed = true
	cfg.ListenPort = 0

	resolver := &btDNSCacheResolver{RefreshTimeout: 5 * time.Minute}
	cfg.TrackerDialContext = resolver.DialContext

	client, err := torrent.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create BT client: %w", err)
	}

	btClient = client
	go resolver.Run(context.Background())
	return btClient, nil
}

func btClientDataDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(cacheDir) == "" {
		cacheDir = os.TempDir()
	}
	return filepath.Join(cacheDir, "ReSys", "bt-client"), nil
}

// Match Gopeed's default file storage behavior: keep part files and infer completion from them.
func newBTStorage(dataDir string) storage.ClientImplCloser {
	return storage.NewFileOpts(storage.NewFileClientOpts{
		ClientBaseDir: dataDir,
		FilePathMaker: func(opts storage.FilePathMakerOpts) string {
			info := opts.Info
			fi := opts.File

			if info == nil {
				if fi != nil && len(fi.Path) > 0 {
					return fi.Path[len(fi.Path)-1]
				}
				return "torrent.data"
			}

			if !info.IsDir() {
				name := info.BestName()
				if name == "" || name == metainfo.NoName {
					if fi != nil && len(fi.Path) > 0 {
						name = fi.Path[len(fi.Path)-1]
					} else {
						name = "torrent.data"
					}
				}
				return name
			}

			if fi != nil {
				comps := append([]string{info.BestName()}, fi.BestPath()...)
				safe, err := storage.ToSafeFilePath(comps...)
				if err != nil {
					return filepath.Join(comps...)
				}
				return safe
			}

			return info.BestName()
		},
		TorrentDirMaker: func(baseDir string, _ *metainfo.Info, _ metainfo.Hash) string {
			return baseDir
		},
	})
}

// Add each tracker in its own tier so slow trackers do not block other announces.
func trackerAnnounceList(trackers []string) [][]string {
	trackers = uniqueStrings(trackers)
	announceList := make([][]string, 0, len(trackers))
	for _, tracker := range trackers {
		announceList = append(announceList, []string{tracker})
	}
	return announceList
}

type btDNSCacheResolver struct {
	RefreshTimeout time.Duration

	resolver dnscache.Resolver
}

func (r *btDNSCacheResolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := r.resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	var (
		conn net.Conn
		dial net.Dialer
	)
	for _, ip := range ips {
		conn, err = dial.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func (r *btDNSCacheResolver) Run(ctx context.Context) {
	ticker := time.NewTicker(r.RefreshTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.resolver.Refresh(true)
		}
	}
}
