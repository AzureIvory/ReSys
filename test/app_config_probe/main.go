package main

import (
	"ReSys/src/config"
	"ReSys/src/disk"
	"ReSys/src/image"
	"ReSys/src/install"
	"ReSys/src/utils"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	probeBuildID   = "app-config-probe-v1"
	probeImageName = "app_config_probe.wim"
)

type probeOptions struct {
	root            string
	imagePath       string
	jsonOnly        bool
	splitTempVolume bool
	splitNeedGiB    float64
}

type probeSnapshot struct {
	BuildID      string                        `json:"build_id"`
	ConfigPath   string                        `json:"config_path"`
	RawPaths     config.AppPathsConfig         `json:"raw_paths"`
	RawImage     config.AppImageConfig         `json:"raw_image"`
	PathFuncs    pathFuncSnapshot              `json:"path_functions"`
	Paths        install.PathConfigSnapshot    `json:"paths"`
	ImageConfig  image.ImageScanConfigSnapshot `json:"image_config"`
	ImageLive    liveImageSnapshot             `json:"image_live"`
	DiskConfig   disk.DiskConfigSnapshot       `json:"disk_config"`
	DiskLive     liveDiskSnapshot              `json:"disk_live"`
	SplitRequest splitRequestSnapshot          `json:"split_request"`
}

type pathFuncSnapshot struct {
	AppDownloadDirName     string `json:"app_download_dir_name"`
	AppPEDirName           string `json:"app_pe_dir_name"`
	AppDriverBackupDirName string `json:"app_driver_backup_dir_name"`
	AppInstallPlanFileName string `json:"app_install_plan_file_name"`
	AppImageHintFileName   string `json:"app_image_hint_file_name"`
	AppTempMarkerRelPath   string `json:"app_temp_marker_relative_path"`
}

type liveImageSnapshot struct {
	Candidates []string `json:"candidates"`
	Error      string   `json:"error,omitempty"`
}

type liveDiskSnapshot struct {
	Candidates        []string `json:"candidates"`
	QueryError        string   `json:"query_error,omitempty"`
	CreatedTempVolume string   `json:"created_temp_volume,omitempty"`
	CreateError       string   `json:"create_error,omitempty"`
}

type splitRequestSnapshot struct {
	Enabled        bool    `json:"enabled"`
	NeedGiB        float64 `json:"need_gib"`
	RequestedBytes uint64  `json:"requested_bytes"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		writeUsage(stderr)
		return 2
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		fmt.Fprintf(stderr, "load app config failed: %v\n", err)
		return 1
	}

	configPath, err := utils.ProjectFile(config.AppConfigRelative)
	if err != nil {
		fmt.Fprintf(stderr, "resolve app config path failed: %v\n", err)
		return 1
	}

	root, err := resolveRoot(opts.root)
	if err != nil {
		fmt.Fprintf(stderr, "resolve root failed: %v\n", err)
		return 1
	}

	imagePath := strings.TrimSpace(opts.imagePath)
	if imagePath == "" {
		imagePath = filepath.Join(root, probeImageName)
	}

	pathSnapshot, err := install.CollectPathConfigSnapshot(imagePath, root)
	if err != nil {
		fmt.Fprintf(stderr, "collect path snapshot failed: %v\n", err)
		return 1
	}

	imageLive := liveImageScan()
	requestedNeedBytes := gibToBytes(opts.splitNeedGiB)
	diskConfig := disk.CollectConfigSnapshot(requestedNeedBytes)
	diskLive := liveDiskScan(opts.splitTempVolume, requestedNeedBytes)

	snapshot := probeSnapshot{
		BuildID:    probeBuildID,
		ConfigPath: configPath,
		RawPaths:   cfg.Paths,
		RawImage:   cfg.Image,
		PathFuncs: pathFuncSnapshot{
			AppDownloadDirName:     install.AppDownloadDirName(),
			AppPEDirName:           install.AppPEDirName(),
			AppDriverBackupDirName: install.AppDriverBackupDirName(),
			AppInstallPlanFileName: install.AppInstallPlanFileName(),
			AppImageHintFileName:   install.AppImageHintFileName(),
			AppTempMarkerRelPath:   install.AppTempMarkerRelativePath(),
		},
		Paths:       pathSnapshot,
		ImageConfig: image.CollectImageScanConfigSnapshot(),
		ImageLive:   imageLive,
		DiskConfig:  diskConfig,
		DiskLive:    diskLive,
		SplitRequest: splitRequestSnapshot{
			Enabled:        opts.splitTempVolume,
			NeedGiB:        opts.splitNeedGiB,
			RequestedBytes: requestedNeedBytes,
		},
	}

	if opts.jsonOnly {
		return writeJSON(stdout, snapshot)
	}

	writeSummary(stdout, root, imagePath, snapshot)
	return 0
}

func parseArgs(args []string) (probeOptions, error) {
	fs := flag.NewFlagSet("app_config_probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var opts probeOptions
	fs.StringVar(&opts.root, "root", "", "volume root used to derive plan/hint/workspace paths, such as D:\\")
	fs.StringVar(&opts.imagePath, "image-path", "", "image path used to derive driver backup workspace")
	fs.BoolVar(&opts.jsonOnly, "json", false, "emit snapshot as JSON only")
	fs.BoolVar(&opts.splitTempVolume, "split-temp-volume", false, "really create a temp volume by calling disk.NewTempVolume")
	fs.Float64Var(&opts.splitNeedGiB, "split-need-gib", 0, "requested temp volume size in GiB before config floor is applied")

	if err := fs.Parse(args); err != nil {
		return probeOptions{}, err
	}
	if fs.NArg() > 0 {
		return probeOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	opts.root = strings.TrimSpace(opts.root)
	opts.imagePath = strings.TrimSpace(opts.imagePath)
	return opts, nil
}

func liveImageScan() liveImageSnapshot {
	paths, err := image.Findimg()
	snapshot := liveImageSnapshot{
		Candidates: append([]string(nil), paths...),
	}
	if err != nil {
		snapshot.Error = err.Error()
	}
	return snapshot
}

func liveDiskScan(create bool, requestedNeedBytes uint64) liveDiskSnapshot {
	snapshot := liveDiskSnapshot{
		Candidates: append([]string(nil), disk.Findpart()...),
	}
	if create {
		root, err := disk.NewTempVolume(requestedNeedBytes)
		if err != nil {
			snapshot.CreateError = err.Error()
			return snapshot
		}
		snapshot.CreatedTempVolume = root
	}
	return snapshot
}

func gibToBytes(gib float64) uint64 {
	if gib <= 0 {
		return 0
	}
	return uint64(gib*1024*1024*1024 + 0.5)
}

func resolveRoot(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("SystemDrive"))
	}
	if raw == "" {
		raw = "C:"
	}
	root, err := utils.NormalizeDrive(raw, 0)
	if err != nil {
		return "", err
	}
	return root, nil
}

func writeJSON(stdout io.Writer, snapshot probeSnapshot) int {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fmt.Fprintf(stdout, "marshal snapshot failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}

func writeSummary(stdout io.Writer, root, imagePath string, snapshot probeSnapshot) {
	fmt.Fprintf(stdout, "[probe] build=%s\n", snapshot.BuildID)
	fmt.Fprintf(stdout, "[probe] config=%s\n", snapshot.ConfigPath)
	fmt.Fprintf(stdout, "[probe] root=%s image=%s\n", root, imagePath)

	fmt.Fprintf(
		stdout,
		"[probe] raw paths: download=%s pe=%s driver=%s plan=%s hint=%s marker=%s\n",
		snapshot.RawPaths.DownloadDirName,
		snapshot.RawPaths.PEDirName,
		snapshot.RawPaths.DriverBackupDirName,
		snapshot.RawPaths.InstallPlan,
		snapshot.RawPaths.ImageHint,
		snapshot.RawPaths.TempMarker,
	)
	fmt.Fprintf(
		stdout,
		"[probe] raw image: depth=%d min_gib=%.2f skip=%s\n",
		snapshot.RawImage.ScanDepth,
		snapshot.RawImage.MinLocalImage,
		strings.Join(snapshot.RawImage.SkipNames, ","),
	)

	fmt.Fprintf(
		stdout,
		"[probe] path funcs: appDownloadDirName()=%s appPEDirName()=%s appDriverBackupDirName()=%s appInstallPlanFileName()=%s appImageHintFileName()=%s appTempMarkerRelativePath()=%s\n",
		snapshot.PathFuncs.AppDownloadDirName,
		snapshot.PathFuncs.AppPEDirName,
		snapshot.PathFuncs.AppDriverBackupDirName,
		snapshot.PathFuncs.AppInstallPlanFileName,
		snapshot.PathFuncs.AppImageHintFileName,
		snapshot.PathFuncs.AppTempMarkerRelPath,
	)
	fmt.Fprintf(
		stdout,
		"[probe] effective paths: download_dir=%s pe_dir=%s driver_dir=%s plan=%s hint=%s marker=%s\n",
		snapshot.Paths.DownloadDirPath,
		snapshot.Paths.PEDirPath,
		snapshot.Paths.DriverBackupRoot,
		snapshot.Paths.InstallPlanPath,
		snapshot.Paths.ImageHintPath,
		snapshot.Paths.TempMarkerPath,
	)
	fmt.Fprintf(
		stdout,
		"[probe] effective image config: depth=%d min_gib=%.2f min_bytes=%d skip=%s\n",
		snapshot.ImageConfig.ScanDepth,
		snapshot.ImageConfig.MinLocalImageGiB,
		snapshot.ImageConfig.MinLocalImageBytes,
		strings.Join(snapshot.ImageConfig.SkipNames, ","),
	)
	fmt.Fprintf(
		stdout,
		"[probe] live image scan: count=%d err=%s candidates=%s\n",
		len(snapshot.ImageLive.Candidates),
		emptyAsDash(snapshot.ImageLive.Error),
		strings.Join(snapshot.ImageLive.Candidates, " | "),
	)
	fmt.Fprintf(
		stdout,
		"[probe] disk config: min_free=%d need_floor=%d requested=%d effective=%d marker=%s\n",
		snapshot.DiskConfig.MinFreeSpaceThreshold,
		snapshot.DiskConfig.NeedFreeSpaceFloor,
		snapshot.DiskConfig.RequestedNeedBytes,
		snapshot.DiskConfig.EffectiveNeedBytes,
		snapshot.DiskConfig.TempMarkerRelativePath,
	)
	fmt.Fprintf(
		stdout,
		"[probe] live disk scan: count=%d candidates=%s\n",
		len(snapshot.DiskLive.Candidates),
		strings.Join(snapshot.DiskLive.Candidates, " | "),
	)
	if snapshot.SplitRequest.Enabled {
		fmt.Fprintf(
			stdout,
			"[probe] live temp volume create: requested_gib=%.2f requested_bytes=%d created=%s err=%s\n",
			snapshot.SplitRequest.NeedGiB,
			snapshot.SplitRequest.RequestedBytes,
			emptyAsDash(snapshot.DiskLive.CreatedTempVolume),
			emptyAsDash(snapshot.DiskLive.CreateError),
		)
	} else {
		fmt.Fprintln(stdout, "[probe] live temp volume create: skipped")
	}
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: app_config_probe [-root D:\\] [-image-path D:\\images\\install.wim] [-json] [-split-temp-volume] [-split-need-gib 12.5]")
}

func emptyAsDash(text string) string {
	if strings.TrimSpace(text) == "" {
		return "-"
	}
	return text
}
