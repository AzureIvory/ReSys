package install

import (
	"ReSys/src/log"
	"ReSys/src/windows"
	"fmt"
)

var driverBackupProbeBackup = backupDrivers
var driverBackupProbeRestore = restoreBackedUpDrivers

// RunDriverBackupProbeBackup runs the formal backup chain with a probe context.
func RunDriverBackupProbeBackup(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}

	ctx := NewInstallContext(plan)
	return driverBackupProbeBackup(ctx)
}

// RunDriverBackupProbeRestore runs the formal restore chain with a probe context.
func RunDriverBackupProbeRestore(plan *InstallPlan) error {
	if plan == nil {
		return fmt.Errorf("install plan is nil")
	}
	if windows.IsWinPE() {
		if recovered, err := RecoverInstallImagePath(plan); err == nil && recovered != "" {
			log.LogWrite(0, "[RunDriverBackupProbeRestore] recovered image path for probe restore: %s", recovered)
		} else if err != nil {
			log.LogWrite(-1, "[RunDriverBackupProbeRestore] recover image path failed, continue with persisted path: %v", err)
		}
	}

	ctx := NewInstallContext(plan)
	return driverBackupProbeRestore(ctx)
}
