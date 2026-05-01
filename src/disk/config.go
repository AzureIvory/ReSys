package disk

import "ReSys/src/config"

var loadDiskAppConfig = config.LoadAppConfig

// tempVolumeExtraBytes 为临时分区额外预留的安全余量。
const tempVolumeExtraBytes uint64 = 512 * 1024 * 1024

type diskPolicy struct {
	minFreeSpace  uint64
	needFreeSpace uint64
	tempMarkerRel string
}

// DiskConfigSnapshot 描述当前 disk 配置的生效结果。
type DiskConfigSnapshot struct {
	MinFreeSpaceThreshold  uint64 `json:"min_free_space_threshold"`
	NeedFreeSpaceFloor     uint64 `json:"need_free_space_floor"`
	RequestedNeedBytes     uint64 `json:"requested_need_bytes"`
	EffectiveNeedBytes     uint64 `json:"effective_need_bytes"`
	TempMarkerRelativePath string `json:"temp_marker_relative_path"`
}

// currentDiskPolicy 返回当前磁盘策略，配置加载失败时回退到 config 包默认值。
func currentDiskPolicy() diskPolicy {
	defCfg := config.DefaultAppConfig()
	def := defCfg.Disk
	policy := diskPolicy{
		minFreeSpace:  def.MinFreeSpace,
		needFreeSpace: def.NeedFreeSpace,
		tempMarkerRel: defCfg.Paths.TempMarker,
	}

	cfg, err := loadDiskAppConfig()
	if err != nil {
		return policy
	}
	if cfg.Disk.MinFreeSpace > 0 {
		policy.minFreeSpace = cfg.Disk.MinFreeSpace
	}
	if cfg.Disk.NeedFreeSpace > 0 {
		policy.needFreeSpace = cfg.Disk.NeedFreeSpace
	}
	if cfg.Paths.TempMarker != "" {
		policy.tempMarkerRel = cfg.Paths.TempMarker
	}
	return policy
}

func minFreeSpaceThreshold() uint64 {
	return currentDiskPolicy().minFreeSpace
}

func tempMarkerRelativePath() string {
	return currentDiskPolicy().tempMarkerRel
}

// CollectConfigSnapshot 返回当前 disk 配置的生效快照。
func CollectConfigSnapshot(requestedNeedBytes uint64) DiskConfigSnapshot {
	policy := currentDiskPolicy()
	return DiskConfigSnapshot{
		MinFreeSpaceThreshold:  policy.minFreeSpace,
		NeedFreeSpaceFloor:     policy.needFreeSpace,
		RequestedNeedBytes:     requestedNeedBytes,
		EffectiveNeedBytes:     resolveTempVolumeNeedBytes(requestedNeedBytes),
		TempMarkerRelativePath: policy.tempMarkerRel,
	}
}

// resolveTempVolumeNeedBytes 先应用配置下限，再应用内置最小值，最后补安全余量。
func resolveTempVolumeNeedBytes(needBytes uint64) uint64 {
	policy := currentDiskPolicy()
	if needBytes < policy.needFreeSpace {
		needBytes = policy.needFreeSpace
	}
	if needBytes < minImageBytes {
		needBytes = minImageBytes
	}
	return needBytes + tempVolumeExtraBytes
}
