package main

import (
	driversvc "ReSys/src/driver"
	"ReSys/src/install"
	"ReSys/src/log"
	"ReSys/src/tools"
	"ReSys/src/windows"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	actionBackup  = "backup"
	actionRestore = "restore"
	probeBuildID  = "driver-probe-driver-sink-v2"
	probeAnchor   = "driver_backup_probe.anchor"
)

var defaultDriverFiles = []string{
	"oem*.inf",
}

var defaultDriverGUIDs = []string{
	"4d36e968-e325-11ce-bfc1-08002be10318",
	"4d36e96b-e325-11ce-bfc1-08002be10318",
	"4d36e96e-e325-11ce-bfc1-08002be10318",
	"4d36e96f-e325-11ce-bfc1-08002be10318",
	"4d36e972-e325-11ce-bfc1-08002be10318",
	"4d36e979-e325-11ce-bfc1-08002be10318",
	"4658ee7e-f050-11d1-b6bd-00c04fa372a7",
	"88BAE032-5A81-49f0-BC3D-A4FF138216D6",
}

var setInstallProbeSink = install.SetDriverBackupProbeSink
var setDriverProbeSink = driversvc.SetProbeSink

type probeOptions struct {
	imagePath  string
	targetRoot string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func writeProbeBanner(stdout io.Writer, action, exePath string) {
	fmt.Fprintf(stdout, "[probe] build=%s\n", probeBuildID)
	fmt.Fprintf(stdout, "[probe] action=%s winpe=%t exe=%s\n", action, windows.IsWinPE(), exePath)
}

func attachProbeSinks(stdout io.Writer) func() {
	restoreInstall := setInstallProbeSink(func(line string) {
		fmt.Fprintln(stdout, line)
	})
	restoreDriver := setDriverProbeSink(func(line string) {
		fmt.Fprintln(stdout, line)
	})
	return func() {
		restoreDriver()
		restoreInstall()
	}
}

func prepareProbeImagePath(action string, opts probeOptions, exePath string, basePlan *install.InstallPlan, stdout io.Writer) (string, error) {
	imagePath := strings.TrimSpace(opts.imagePath)
	if imagePath != "" {
		return imagePath, nil
	}

	if action == actionRestore {
		if basePlan != nil && strings.TrimSpace(basePlan.ImagePath) != "" {
			return strings.TrimSpace(basePlan.ImagePath), nil
		}
		return "", nil
	}

	anchorPath := filepath.Join(filepath.Dir(exePath), probeAnchor)
	if err := os.WriteFile(anchorPath, []byte(probeBuildID+"\n"), 0o644); err != nil {
		return "", err
	}

	fmt.Fprintf(stdout, "[probe] prepared workspace anchor=%s\n", anchorPath)
	log.LogWrite(0, "[driver_backup_probe] prepared workspace anchor: %s", anchorPath)
	return anchorPath, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	defer log.CloseLog()

	action, opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		writeUsage(stderr)
		return 2
	}

	if !tools.IsAdmin() {
		fmt.Fprintln(stderr, "driver_backup_probe requires administrator privileges")
		return 1
	}

	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "resolve executable path failed: %v\n", err)
		return 1
	}

	writeProbeBanner(stdout, action, exePath)
	log.LogWrite(0, "[driver_backup_probe] start: action=%s winpe=%t exe=%s", action, windows.IsWinPE(), exePath)

	restoreSinks := attachProbeSinks(stdout)
	defer restoreSinks()

	var basePlan *install.InstallPlan
	loadedPlan, loadErr := install.LoadInstallPlan()
	if loadErr == nil {
		basePlan = loadedPlan
		fmt.Fprintf(stdout, "[probe] loaded saved plan: image=%s target=%s\n", loadedPlan.ImagePath, loadedPlan.TargetRoot)
		log.LogWrite(0, "[driver_backup_probe] loaded saved plan: image=%s target=%s", loadedPlan.ImagePath, loadedPlan.TargetRoot)
	} else {
		fmt.Fprintf(stdout, "[probe] saved plan unavailable: %v\n", loadErr)
		log.LogWrite(-1, "[driver_backup_probe] saved plan unavailable: %v", loadErr)
	}

	imagePath, err := prepareProbeImagePath(action, opts, exePath, basePlan, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "prepare probe image path failed: %v\n", err)
		return 1
	}

	plan := buildProbePlan(action, imagePath, opts.targetRoot, basePlan)

	if action == actionRestore && basePlan == nil && strings.TrimSpace(opts.imagePath) == "" {
		fmt.Fprintln(stderr, "restore requires an existing saved plan or -image-path")
		return 1
	}
	if action == actionRestore && strings.TrimSpace(plan.TargetRoot) == "" {
		fmt.Fprintln(stderr, "restore requires -target-root or a saved plan with target_root")
		return 1
	}

	fmt.Fprintf(
		stdout,
		"[probe] assembled plan: image=%s target=%s backup=%t restore=%t file_rules=%d guid_rules=%d\n",
		plan.ImagePath,
		plan.TargetRoot,
		plan.Flags.NeedBackupBeforePE,
		plan.Flags.NeedOfflineDrivers,
		len(plan.DriverFiles),
		len(plan.DriverGUIDs),
	)
	log.LogWrite(
		0,
		"[driver_backup_probe] assembled plan: image=%s target=%s backup=%t restore=%t file_rules=%d guid_rules=%d",
		plan.ImagePath,
		plan.TargetRoot,
		plan.Flags.NeedBackupBeforePE,
		plan.Flags.NeedOfflineDrivers,
		len(plan.DriverFiles),
		len(plan.DriverGUIDs),
	)
	if snapshot, snapErr := install.CollectDriverBackupSnapshotForPlan(plan); snapErr == nil {
		writeSnapshotSummary(stdout, "preflight", snapshot)
	} else {
		fmt.Fprintf(stdout, "[probe] snapshot preflight error=%v\n", snapErr)
		log.LogWrite(-1, "[driver_backup_probe] preflight snapshot failed: %v", snapErr)
	}

	switch action {
	case actionBackup:
		fmt.Fprintln(stdout, "[probe] stage=backup start")
		if err := install.RunDriverBackupProbeBackup(plan); err != nil {
			if snapshot, snapErr := install.CollectDriverBackupSnapshotForPlan(plan); snapErr == nil {
				writeSnapshotSummary(stdout, "backup-failed", snapshot)
			}
			fmt.Fprintf(stderr, "[probe] stage=backup failed: %v\n", err)
			log.LogWrite(-2, "[driver_backup_probe] backup failed: %v", err)
			return 1
		}
		if snapshot, snapErr := install.CollectDriverBackupSnapshotForPlan(plan); snapErr == nil {
			writeSnapshotSummary(stdout, "backup-final", snapshot)
		}
		fmt.Fprintln(stdout, "[probe] stage=backup done")
		log.LogWrite(0, "[driver_backup_probe] backup completed")
	case actionRestore:
		fmt.Fprintln(stdout, "[probe] stage=restore start")
		if err := install.RunDriverBackupProbeRestore(plan); err != nil {
			if snapshot, snapErr := install.CollectDriverBackupSnapshotForPlan(plan); snapErr == nil {
				writeSnapshotSummary(stdout, "restore-failed", snapshot)
			}
			fmt.Fprintf(stderr, "[probe] stage=restore failed: %v\n", err)
			log.LogWrite(-2, "[driver_backup_probe] restore failed: %v", err)
			return 1
		}
		if snapshot, snapErr := install.CollectDriverBackupSnapshotForPlan(plan); snapErr == nil {
			writeSnapshotSummary(stdout, "restore-source-final", snapshot)
		}
		fmt.Fprintln(stdout, "[probe] stage=restore done")
		log.LogWrite(0, "[driver_backup_probe] restore completed")
	default:
		fmt.Fprintf(stderr, "unsupported action: %s\n", action)
		return 2
	}

	return 0
}

func parseArgs(args []string) (string, probeOptions, error) {
	if len(args) == 0 {
		return "", probeOptions{}, fmt.Errorf("missing action")
	}

	action := strings.ToLower(strings.TrimSpace(args[0]))
	if action != actionBackup && action != actionRestore {
		return "", probeOptions{}, fmt.Errorf("unsupported action %q", action)
	}

	fs := flag.NewFlagSet("driver_backup_probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var opts probeOptions
	fs.StringVar(&opts.imagePath, "image-path", "", "probe image path used to locate driverbackup")
	fs.StringVar(&opts.targetRoot, "target-root", "", "offline target root used during restore, such as D:\\")

	if err := fs.Parse(args[1:]); err != nil {
		return "", probeOptions{}, err
	}
	if fs.NArg() > 0 {
		return "", probeOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	opts.imagePath = strings.TrimSpace(opts.imagePath)
	opts.targetRoot = strings.TrimSpace(opts.targetRoot)
	return action, opts, nil
}

func buildProbePlan(action, imagePath, targetRoot string, base *install.InstallPlan) *install.InstallPlan {
	plan := clonePlan(base)
	if strings.TrimSpace(string(plan.Mode)) == "" {
		plan.Mode = install.ReinstallModeAuto
	}

	if strings.TrimSpace(imagePath) != "" {
		plan.ImagePath = strings.TrimSpace(imagePath)
	}
	if strings.TrimSpace(targetRoot) != "" {
		plan.TargetRoot = strings.TrimSpace(targetRoot)
	}

	plan.DriverFiles = append([]string{}, defaultDriverFiles...)
	plan.DriverGUIDs = append([]string{}, defaultDriverGUIDs...)

	switch action {
	case actionBackup:
		plan.Flags.NeedBackupBeforePE = true
		plan.Flags.NeedOfflineDrivers = true
	case actionRestore:
		plan.Flags.NeedBackupBeforePE = false
		plan.Flags.NeedOfflineDrivers = true
	}

	return plan
}

func clonePlan(base *install.InstallPlan) *install.InstallPlan {
	if base == nil {
		return &install.InstallPlan{}
	}

	plan := *base
	plan.DriverFiles = append([]string{}, base.DriverFiles...)
	plan.DriverGUIDs = append([]string{}, base.DriverGUIDs...)
	plan.Files = append([]install.InstallFile{}, base.Files...)
	plan.Shortcuts = append([]install.InstallShortcut{}, base.Shortcuts...)
	return &plan
}

func writeSnapshotSummary(w io.Writer, label string, snapshot install.DriverBackupSnapshot) {
	fmt.Fprintf(
		w,
		"[probe] snapshot %s root=%s exists=%t dirs=%d files=%d infs=%d empty_dirs=%d guid_dirs=%d\n",
		label,
		snapshot.Root,
		snapshot.Exists,
		snapshot.SubdirCount,
		snapshot.FileCount,
		snapshot.INFCount,
		len(snapshot.EmptyDirs),
		len(snapshot.GUIDINFCounts),
	)

	for idx, dir := range snapshot.EmptyDirs {
		fmt.Fprintf(w, "[probe] snapshot %s empty_dir[%d]=%s\n", label, idx+1, dir)
	}

	if len(snapshot.GUIDINFCounts) > 0 {
		keys := make([]string, 0, len(snapshot.GUIDINFCounts))
		for key := range snapshot.GUIDINFCounts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "[probe] snapshot %s guid_inf_counts:\n", label)
		for _, key := range keys {
			fmt.Fprintf(w, "[probe] snapshot %s %s=%d\n", label, key, snapshot.GUIDINFCounts[key])
		}
	}
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  driver_backup_probe backup [-image-path PATH] [-target-root ROOT]")
	fmt.Fprintln(w, "  driver_backup_probe restore [-target-root ROOT] [-image-path PATH]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  backup creates a small workspace anchor next to the probe when no -image-path is provided.")
	fmt.Fprintln(w, "  restore prefers the saved plan written by backup; in PE, pass -target-root such as D:\\ when needed.")
}
