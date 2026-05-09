package driver

import (
	"ReSys/src/file"
	"ReSys/src/log"
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	D "ReSys/src/dism"
	"ReSys/src/utils"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var dism, _ = D.Default().GetDismCmd()

const (
	DIGCF_PRESENT    = 0x00000002
	DIGCF_ALLCLASSES = 0x00000004
	DICS_FLAG_GLOBAL = 0x00000001
	DIREG_DRV        = 0x00000002

	SPDRP_HARDWAREID  = 0x00000001
	SPDRP_DEVICEDESC  = 0x00000000
	SPDRP_MFG         = 0x0000000B
	SPDRP_CLASS       = 0x00000007
	SPDRP_CLASSGUID   = 0x00000008
	SPDRP_DRIVER      = 0x00000009
	ERROR_NO_MORE     = 259
	ERROR_INSUFF_BUFS = 122

	REG_SZ       = 1
	REG_MULTI_SZ = 7

	INSTALLFLAG_FORCE          = 0x00000001
	INSTALLFLAG_READONLY       = 0x00000002
	INSTALLFLAG_NONINTERACTIVE = 0x00000004

	SP_COPY_NOOVERWRITE           = 0x00000008
	SP_COPY_OEMINF_CATALOG_ONLY   = 0x00040000
	SPOST_PATH                    = 1
	SUOI_FORCEDELETE              = 1
	OFFLINE_SERVICE_TYPE_DEFAULT  = 1 // SERVICE_KERNEL_DRIVER
	OFFLINE_START_TYPE_DEFAULT    = 3 // SERVICE_DEMAND_START
	OFFLINE_ERROR_CONTROL_DEFAULT = 1 // SERVICE_ERROR_NORMAL
)

// DriverInfo 是从系统枚举出来的驱动/设备对应 INF 信息（在线系统）。
type DriverInfo struct {
	Description  string
	Manufacturer string
	InfPath      string
	HardwareID   string
	DeviceClass  string
	ClassGUID    string
	IsOEM        bool
	DriverRegKey string
}

// SP_DEVINFO_DATA 是 SetupAPI 枚举设备时需要的结构体（对应 Windows 的 SP_DEVINFO_DATA）。
type SP_DEVINFO_DATA struct {
	CbSize    uint32
	ClassGuid windows.GUID
	DevInst   uint32
	Reserved  uintptr
}

// setupAPI 封装 setupapi.dll 的动态调用：用于枚举设备、取注册表属性、复制/卸载 OEM INF 等。
type setupAPI struct {
	dll *windows.LazyDLL

	pSetupDiGetClassDevsW              *windows.LazyProc
	pSetupDiEnumDeviceInfo             *windows.LazyProc
	pSetupDiGetDeviceRegistryPropertyW *windows.LazyProc
	pSetupDiDestroyDeviceInfoList      *windows.LazyProc
	pSetupDiOpenDevRegKey              *windows.LazyProc
	pSetupCopyOEMInfW                  *windows.LazyProc
	pSetupUninstallOEMInfW             *windows.LazyProc

	// Win8+ 才有：Win7 上 Find 会失败
	pSetupGetInfDriverStoreLocationW *windows.LazyProc
}

// newSetupAPI 创建 setupAPI 的 LazyDLL/LazyProc（不立即 Load，按需 Load）。
func newSetupAPI() *setupAPI {
	d := windows.NewLazySystemDLL("setupapi.dll")
	return &setupAPI{
		dll:                                d,
		pSetupDiGetClassDevsW:              d.NewProc("SetupDiGetClassDevsW"),
		pSetupDiEnumDeviceInfo:             d.NewProc("SetupDiEnumDeviceInfo"),
		pSetupDiGetDeviceRegistryPropertyW: d.NewProc("SetupDiGetDeviceRegistryPropertyW"),
		pSetupDiDestroyDeviceInfoList:      d.NewProc("SetupDiDestroyDeviceInfoList"),
		pSetupDiOpenDevRegKey:              d.NewProc("SetupDiOpenDevRegKey"),
		pSetupCopyOEMInfW:                  d.NewProc("SetupCopyOEMInfW"),
		pSetupUninstallOEMInfW:             d.NewProc("SetupUninstallOEMInfW"),
		pSetupGetInfDriverStoreLocationW:   d.NewProc("SetupGetInfDriverStoreLocationW"),
	}
}

// newDevAPI 封装 newdev.dll：用于真正“安装/更新”驱动（DiInstallDriverW / UpdateDriverForPlugAndPlayDevicesW）。
type newDevAPI struct {
	dll *windows.LazyDLL

	pDiInstallDriverW            *windows.LazyProc
	pUpdateDriverForPlugAndPlayW *windows.LazyProc
}

// newNewDevAPI 加载 newdev.dll 并准备过程地址。
// 如果系统缺失 newdev.dll（极少），返回 error；上层允许 newdev 为 nil 再走 fallback。
func newNewDevAPI() (*newDevAPI, error) {
	d := windows.NewLazySystemDLL("newdev.dll")
	if err := d.Load(); err != nil {
		log.LogWrite(-2, "[newNewDevAPI]加载newdev.dll失败: err=%v", err)
		return nil, err
	}
	return &newDevAPI{
		dll:                          d,
		pDiInstallDriverW:            d.NewProc("DiInstallDriverW"),
		pUpdateDriverForPlugAndPlayW: d.NewProc("UpdateDriverForPlugAndPlayDevicesW"),
	}, nil
}

// utf16PtrToString 把 *uint16 的 UTF-16 以 \0 结尾字符串安全转为 Go string。
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

// bytesToUTF16Slice 把 SetupAPI 返回的 byte buffer（UTF-16LE）按 byteLen 转成 []uint16 视图。
// 注意：byteLen 通常来自 required（单位是字节），这里按 2 字节切 uint16。
func bytesToUTF16Slice(b []byte, byteLen uint32) []uint16 {
	n := int(byteLen / 2)
	if n <= 0 {
		return nil
	}
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), n)
	return u16
}

// getDeviceRegistryPropertyString 读取 SetupAPI 设备属性（REG_SZ / REG_MULTI_SZ）并返回字符串值。
// - prop: SPDRP_* 常量
// - 返回：字符串、注册表类型、错误
// - 实现：先用小 buffer，遇到 ERROR_INSUFFICIENT_BUFFER 再扩容重试。
func (s *setupAPI) getDeviceRegistryPropertyString(hDevInfo windows.Handle, devInfoData *SP_DEVINFO_DATA, prop uint32) (string, uint32, error) {
	var regType uint32
	var required uint32

	bufSize := uint32(512)
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, bufSize)
		r1, _, e1 := s.pSetupDiGetDeviceRegistryPropertyW.Call(
			uintptr(hDevInfo),
			uintptr(unsafe.Pointer(devInfoData)),
			uintptr(prop),
			uintptr(unsafe.Pointer(&regType)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&required)),
		)
		if r1 != 0 {
			// 成功，根据 regType 解析 buffer
			if regType == REG_SZ {
				u16 := bytesToUTF16Slice(buf, required)
				return windows.UTF16ToString(u16), regType, nil
			}
			if regType == REG_MULTI_SZ {
				u16 := bytesToUTF16Slice(buf, required)
				parts := utils.ParseMultiSz(u16) // 解析 MULTI_SZ（双零结尾）为 []string
				if len(parts) > 0 {
					return parts[0], regType, nil // 取第一个（和你 Rust 逻辑一致）
				}
				return "", regType, nil
			}
			return "", regType, nil
		}

		// 失败：判断是否需要扩容重试
		if isWindowsErrorCode(e1, ERROR_INSUFF_BUFS) && required > bufSize {
			bufSize = required + 2
			continue
		}
		return "", regType, e1
	}

	return "", regType, errors.New("SetupDiGetDeviceRegistryPropertyW: buffer retry exhausted")
}

func (s *setupAPI) getDevicePublishedInfPath(hDevInfo windows.Handle, devInfoData *SP_DEVINFO_DATA) (string, error) {
	if err := s.dll.Load(); err != nil {
		return "", err
	}

	r1, _, e1 := s.pSetupDiOpenDevRegKey.Call(
		uintptr(hDevInfo),
		uintptr(unsafe.Pointer(devInfoData)),
		uintptr(DICS_FLAG_GLOBAL),
		0,
		uintptr(DIREG_DRV),
		uintptr(registry.QUERY_VALUE),
	)
	if r1 == 0 || r1 == uintptr(windows.InvalidHandle) {
		return "", e1
	}

	key := registry.Key(r1)
	defer key.Close()

	infPath, _, err := key.GetStringValue("InfPath")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(filepath.Base(infPath)), nil
}

// enumerateDrivers 使用 SetupAPI 枚举“当前在线系统”所有已存在设备，并读出它们关联的 INF、描述、硬件 ID 等信息。
func (s *setupAPI) enumerateDrivers() ([]DriverInfo, error) {
	emitDriverProbeLogf(0, "[setup.enumerateDrivers] enter")
	if err := s.dll.Load(); err != nil {
		emitDriverProbeLogf(-2, "[setup.enumerateDrivers] setupapi.dll load failed: err=%v", err)
		return nil, err
	}
	emitDriverProbeLogf(0, "[setup.enumerateDrivers] setupapi.dll loaded")

	// HDEVINFO SetupDiGetClassDevsW(NULL,NULL,NULL, DIGCF_PRESENT|DIGCF_ALLCLASSES)
	emitDriverProbeLogf(0, "[setup.enumerateDrivers] call SetupDiGetClassDevsW flags=%d", DIGCF_PRESENT|DIGCF_ALLCLASSES)
	r1, _, e1 := s.pSetupDiGetClassDevsW.Call(0, 0, 0, uintptr(DIGCF_PRESENT|DIGCF_ALLCLASSES))
	hDevInfo := windows.Handle(r1)
	if hDevInfo == windows.InvalidHandle || hDevInfo == 0 {
		emitDriverProbeLogf(-2, "[setup.enumerateDrivers] SetupDiGetClassDevsW failed: err=%v", e1)
		return nil, fmt.Errorf("SetupDiGetClassDevsW failed: %w", e1)
	}
	emitDriverProbeLogf(0, "[setup.enumerateDrivers] SetupDiGetClassDevsW ok: handle=%v", hDevInfo)
	defer s.pSetupDiDestroyDeviceInfoList.Call(uintptr(hDevInfo))

	var out []DriverInfo
	for idx := uint32(0); ; idx++ {
		if idx < 5 || idx%100 == 0 {
			emitDriverProbeLogf(0, "[setup.enumerateDrivers] enum call idx=%d", idx)
		}
		var dev SP_DEVINFO_DATA
		dev.CbSize = uint32(unsafe.Sizeof(dev))

		r2, _, e2 := s.pSetupDiEnumDeviceInfo.Call(
			uintptr(hDevInfo),
			uintptr(idx),
			uintptr(unsafe.Pointer(&dev)),
		)
		if r2 == 0 {
			if isWindowsErrorCode(e2, ERROR_NO_MORE) {
				emitDriverProbeLogf(0, "[setup.enumerateDrivers] no more devices at idx=%d total=%d", idx, len(out))
				break
			}
			emitDriverProbeLogf(-2, "[setup.enumerateDrivers] SetupDiEnumDeviceInfo failed: idx=%d err=%v", idx, e2)
			return nil, fmt.Errorf("SetupDiEnumDeviceInfo failed at idx=%d: %w", idx, e2)
		}

		// INF_PATH 为空的设备跳过
		/*
			// legacy broken line kept here only to preserve nearby comments during patching
		*/
		inf, infErr := s.getDevicePublishedInfPath(hDevInfo, &dev)
		if strings.TrimSpace(inf) == "" {
			if idx < 5 || idx%100 == 0 {
				emitDriverProbeLogf(0, "[setup.enumerateDrivers] skip empty inf: idx=%d err=%v", idx, infErr)
			}
			continue
		}

		// 其它属性尽力读取，读取失败就返回空
		desc, _, _ := s.getDeviceRegistryPropertyString(hDevInfo, &dev, SPDRP_DEVICEDESC)
		mfg, _, _ := s.getDeviceRegistryPropertyString(hDevInfo, &dev, SPDRP_MFG)
		hwid, _, _ := s.getDeviceRegistryPropertyString(hDevInfo, &dev, SPDRP_HARDWAREID)
		class, _, _ := s.getDeviceRegistryPropertyString(hDevInfo, &dev, SPDRP_CLASS)
		cguid, _, _ := s.getDeviceRegistryPropertyString(hDevInfo, &dev, SPDRP_CLASSGUID)
		driverKey, _, _ := s.getDeviceRegistryPropertyString(hDevInfo, &dev, SPDRP_DRIVER)

		// 简单判断 INF 是否为 oemXX.inf
		isOEM := strings.HasPrefix(strings.ToLower(filepath.Base(inf)), "oem") && strings.HasSuffix(strings.ToLower(filepath.Base(inf)), ".inf")
		emitDriverProbeLogf(
			0,
			"[setup.enumerateDrivers] item idx=%d inf=%s isOEM=%t class=%s classGuid=%s desc=%s",
			idx,
			inf,
			isOEM,
			class,
			cguid,
			desc,
		)

		out = append(out, DriverInfo{
			Description:  desc,
			Manufacturer: mfg,
			InfPath:      inf,
			HardwareID:   hwid,
			DeviceClass:  class,
			ClassGUID:    cguid,
			IsOEM:        isOEM,
			DriverRegKey: driverKey,
		})
	}
	emitDriverProbeLogf(0, "[setup.enumerateDrivers] completed total=%d", len(out))
	return out, nil
}

// setupCopyOEMInf 调用 SetupCopyOEMInfW：把指定 INF “复制/导入”到系统 INF 仓库（入库），并返回目标 INF 路径/名称。
func (s *setupAPI) setupCopyOEMInf(infPath string) (string, error) {
	if err := s.dll.Load(); err != nil {
		return "", err
	}
	pInf, err := windows.UTF16PtrFromString(infPath)
	if err != nil {
		return "", err
	}

	dest := make([]uint16, 260)
	var required uint32

	r1, _, e1 := s.pSetupCopyOEMInfW.Call(
		uintptr(unsafe.Pointer(pInf)),
		0,
		uintptr(SPOST_PATH),
		0,
		uintptr(unsafe.Pointer(&dest[0])),
		uintptr(uint32(len(dest))),
		uintptr(unsafe.Pointer(&required)),
		0,
	)
	if r1 == 0 {
		return "", fmt.Errorf("SetupCopyOEMInfW failed: %v (winerr=%v)", e1, windows.GetLastError())
	}
	return windows.UTF16ToString(dest), nil
}

// setupUninstallOEMInf 调用 SetupUninstallOEMInfW：卸载/删除指定 oemXX.inf（强制删除）。
func (s *setupAPI) setupUninstallOEMInf(infName string) error {
	if err := s.dll.Load(); err != nil {
		return err
	}
	pName, err := windows.UTF16PtrFromString(infName)
	if err != nil {
		return err
	}
	r1, _, e1 := s.pSetupUninstallOEMInfW.Call(
		uintptr(unsafe.Pointer(pName)),
		uintptr(SUOI_FORCEDELETE),
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("SetupUninstallOEMInfW failed: %v (winerr=%v)", e1, windows.GetLastError())
	}
	return nil
}

// tryGetInfDriverStoreLocation 尝试调用 Win8+ 的 SetupGetInfDriverStoreLocationW 获取 INF 在 DriverStore 的真实路径。
// - Win7 上该 API 不存在（Find 失败），返回 ("", false)
// - 成功返回 (path, true)
func (s *setupAPI) tryGetInfDriverStoreLocation(infNameOrPath string) (string, bool) {
	if err := s.dll.Load(); err != nil {
		return "", false
	}
	if err := s.pSetupGetInfDriverStoreLocationW.Find(); err != nil {
		return "", false
	}

	base := filepath.Base(infNameOrPath)
	pName, err := windows.UTF16PtrFromString(base)
	if err != nil {
		return "", false
	}

	buf := make([]uint16, 520)
	var required uint32
	r1, _, _ := s.pSetupGetInfDriverStoreLocationW.Call(
		uintptr(unsafe.Pointer(pName)),
		0,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(uint32(len(buf))),
		uintptr(unsafe.Pointer(&required)),
	)
	if r1 == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf), true
}

// installDriver 使用 newdev.dll 的 DiInstallDriverW “真正安装”一个 INF。
// 返回 needReboot 表示是否需要重启。
// 注意：Windows BOOL 用 windows.BOOL；返回时用 reboot!=0 转 bool。
func (n *newDevAPI) installDriver(infPath string, force bool) (needReboot bool, err error) {
	pInf, err := windows.UTF16PtrFromString(infPath)
	if err != nil {
		return false, err
	}

	var reboot uint32 // Windows BOOL
	flags := uint32(INSTALLFLAG_NONINTERACTIVE)
	if force {
		flags |= INSTALLFLAG_FORCE
	}

	r1, _, e1 := n.pDiInstallDriverW.Call(
		0,
		uintptr(unsafe.Pointer(pInf)),
		uintptr(flags),
		uintptr(unsafe.Pointer(&reboot)),
	)
	if r1 == 0 {
		return false, fmt.Errorf("DiInstallDriverW failed: %v (winerr=%v)", e1, windows.GetLastError())
	}
	return reboot != 0, nil
}

// updatePnPDriver 使用 UpdateDriverForPlugAndPlayDevicesW：针对某个硬件 ID 更新 PnP 驱动。
// 返回：needReboot、updated（是否确实更新了）、error。
func (n *newDevAPI) updatePnPDriver(hardwareID, infPath string, force bool) (needReboot bool, updated bool, err error) {
	pHW, err := windows.UTF16PtrFromString(hardwareID)
	if err != nil {
		return false, false, err
	}
	pInf, err := windows.UTF16PtrFromString(infPath)
	if err != nil {
		return false, false, err
	}

	var reboot uint32 // Windows BOOL
	var flags uint32
	if force {
		flags = INSTALLFLAG_FORCE
	}

	r1, _, e1 := n.pUpdateDriverForPlugAndPlayW.Call(
		0,
		uintptr(unsafe.Pointer(pHW)),
		uintptr(unsafe.Pointer(pInf)),
		uintptr(flags),
		uintptr(unsafe.Pointer(&reboot)),
	)
	if r1 == 0 {
		if windows.GetLastError() == syscall.Errno(0) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("UpdateDriverForPlugAndPlayDevicesW failed: %v (winerr=%v)", e1, windows.GetLastError())
	}
	return reboot != 0, true, nil
}

// DriverManager 是对外的“驱动管理器”：封装 SetupAPI / NewDev 的组合能力（枚举、导出、导入等）。
type DriverManager struct {
	setup  *setupAPI
	newdev *newDevAPI // 可选：newdev.dll 不可用时为 nil
}

// NewDriverManager 创建驱动管理器：SetupAPI 必有；NewDev 可选（加载失败则为 nil）。
func NewDriverManager() (*DriverManager, error) {
	s := newSetupAPI()
	emitDriverProbeLogf(0, "[NewDriverManager] setup initialized")
	n, nErr := newNewDevAPI() // 允许缺失
	if nErr != nil {
		emitDriverProbeLogf(-1, "[NewDriverManager] newdev unavailable, fallback path enabled: err=%v", nErr)
		log.LogWrite(-1, "[NewDriverManager]newdev不可用，回退兼容流程: err=%v", nErr)
	}
	emitDriverProbeLogf(0, "[NewDriverManager] ready: newdev=%t", n != nil)
	return &DriverManager{setup: s, newdev: n}, nil
}

// EnumerateAllDrivers 枚举当前在线系统“所有设备关联的 INF/驱动信息”。
func (m *DriverManager) EnumerateAllDrivers() ([]DriverInfo, error) {
	return m.setup.enumerateDrivers()
}

func (m *DriverManager) EnumerateDriversByClassGUID(classGUID string) ([]DriverInfo, error) {
	all, err := m.EnumerateAllDrivers()
	if err != nil {
		return nil, err
	}

	target, err := NormalizeClassGUID(classGUID)
	if err != nil {
		return nil, err
	}
	if target == "" {
		return all, nil
	}

	var out []DriverInfo
	for _, d := range all {
		if strings.EqualFold(strings.TrimSpace(d.ClassGUID), target) {
			out = append(out, d)
		}
	}
	return out, nil
}

// NormalizeClassGUID 规范化设备类 GUID，返回带大括号的大写标准形式。
func NormalizeClassGUID(classGUID string) (string, error) {
	classGUID = strings.TrimSpace(classGUID)
	if classGUID == "" {
		return "", nil
	}
	if !strings.HasPrefix(classGUID, "{") {
		classGUID = "{" + classGUID
	}
	if !strings.HasSuffix(classGUID, "}") {
		classGUID += "}"
	}
	parsed, err := windows.GUIDFromString(classGUID)
	if err != nil {
		return "", fmt.Errorf("invalid class guid %q: %w", classGUID, err)
	}
	return parsed.String(), nil
}

// ParseFilePatterns 按文本框协议拆分 INF 通配规则。
// 支持换行、逗号、分号分隔，返回规范化并去重后的规则列表。
func ParseFilePatterns(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	return NormalizeINFPatterns(parts)
}

// EnumerateOEMDrivers 枚举当前在线系统中 INF 为 oemXX.inf 的第三方驱动条目。
func (m *DriverManager) EnumerateOEMDrivers() ([]DriverInfo, error) {
	emitDriverProbeLogf(0, "[EnumerateOEMDrivers] start")
	all, err := m.setup.enumerateDrivers()
	if err != nil {
		emitDriverProbeLogf(-2, "[EnumerateOEMDrivers] enumerate all drivers failed: err=%v", err)
		return nil, err
	}
	emitDriverProbeLogf(0, "[EnumerateOEMDrivers] enumerated all drivers: total=%d", len(all))
	var out []DriverInfo
	for _, d := range all {
		if d.IsOEM {
			out = append(out, d)
		}
	}
	emitDriverProbeLogf(0, "[EnumerateOEMDrivers] completed: oem=%d skipped_non_oem=%d", len(out), len(all)-len(out))
	return out, nil
}

// NormalizeINFPatterns 规范化并去重 INF 通配规则，统一转成小写文件名形式。
func NormalizeINFPatterns(pats []string) []string {
	if len(pats) == 0 {
		return nil
	}

	out := make([]string, 0, len(pats))
	seen := map[string]struct{}{}
	for _, pat := range pats {
		pat = strings.ToLower(strings.TrimSpace(filepath.Base(pat)))
		if pat == "" || pat == "." {
			continue
		}
		if _, ok := seen[pat]; ok {
			continue
		}
		seen[pat] = struct{}{}
		out = append(out, pat)
	}
	return out
}

// MatchINF 判断给定 INF 文件名是否命中任一发布名规则。
func MatchINF(name string, pats []string) bool {
	name = strings.ToLower(strings.TrimSpace(filepath.Base(name)))
	if name == "" {
		return false
	}
	pats = NormalizeINFPatterns(pats)
	for _, pat := range pats {
		if ok, err := filepath.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

// pickPat 从驱动列表中筛出发布 INF 名匹配规则的条目。
func pickPat(list []DriverInfo, pats []string) []DriverInfo {
	pats = NormalizeINFPatterns(pats)
	if len(pats) == 0 {
		return append([]DriverInfo{}, list...)
	}

	out := make([]DriverInfo, 0, len(list))
	for _, drv := range list {
		if MatchINF(drv.InfPath, pats) {
			out = append(out, drv)
		}
	}
	return out
}

// ExportByINFs 按系统里的发布 INF 名规则导出 OEM 驱动包。
func (m *DriverManager) ExportByINFs(dst string, pats []string) (int, error) {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		emitDriverProbeLogf(-2, "[ExportByINFs] create dir failed: dir=%s err=%v", dst, err)
		return 0, err
	}

	pats = NormalizeINFPatterns(pats)
	emitDriverProbeLogf(0, "[ExportByINFs] enumerate start: destination=%s patterns=%v", dst, pats)
	list, err := m.EnumerateOEMDrivers()
	if err != nil {
		emitDriverProbeLogf(-2, "[ExportByINFs] enumerate OEM drivers failed: err=%v", err)
		return 0, err
	}
	emitDriverProbeLogf(0, "[ExportByINFs] start: destination=%s patterns=%v enumerated=%d", dst, pats, len(list))

	hits := pickPat(list, pats)
	emitDriverProbeLogf(0, "[ExportByINFs] selected=%d skipped=%d", len(hits), len(list)-len(hits))

	seen := map[string]struct{}{}
	okCnt := 0

	for idx, drv := range list {
		pub := filepath.Base(drv.InfPath)
		hit := MatchINF(pub, pats)
		emitDriverProbeLogf(
			0,
			"[ExportByINFs] item[%d/%d]: publishedInf=%s matched=%t desc=%s class=%s",
			idx+1,
			len(list),
			pub,
			hit,
			drv.Description,
			drv.DeviceClass,
		)
		if !hit {
			continue
		}

		key := strings.ToLower(filepath.Base(drv.InfPath))
		if _, ok := seen[key]; ok {
			emitDriverProbeLogf(0, "[ExportByINFs] skip duplicate: publishedInf=%s", pub)
			continue
		}
		seen[key] = struct{}{}

		src := m.resolveDriverStoreInfPath(drv.InfPath)
		if src == "" {
			emitDriverProbeLogf(0, "[ExportByINFs] resolve store inf empty, fallback to Windows\\INF: publishedInf=%s", pub)
			src = filepath.Join(filepath.Join(utils.WindowsDir(), "INF"), filepath.Base(drv.InfPath))
		} else {
			emitDriverProbeLogf(0, "[ExportByINFs] resolved store inf: publishedInf=%s storeInf=%s", pub, src)
		}
		if _, err := os.Stat(src); err != nil {
			emitDriverProbeLogf(-1, "[ExportByINFs] skip missing source: publishedInf=%s storeInf=%s err=%v", pub, src, err)
			continue
		}

		stem := strings.TrimSuffix(filepath.Base(drv.InfPath), filepath.Ext(drv.InfPath))
		pkgDir := filepath.Join(dst, stem)
		_ = os.MkdirAll(pkgDir, 0o755)
		emitDriverProbeLogf(0, "[ExportByINFs] copy start: publishedInf=%s source=%s dst=%s", pub, src, pkgDir)

		if err := m.copyDriverPackage(src, pkgDir); err == nil {
			okCnt++
			infs, findErr := findInfFiles(pkgDir)
			if findErr != nil {
				emitDriverProbeLogf(-1, "[ExportByINFs] copy done but count inf failed: publishedInf=%s dst=%s err=%v", pub, pkgDir, findErr)
			}
			emitDriverProbeLogf(0, "[ExportByINFs] copy done: publishedInf=%s dst=%s infs=%d", pub, pkgDir, len(infs))
			continue
		} else {
			emitDriverProbeLogf(-2, "[ExportByINFs] copy failed: publishedInf=%s source=%s dst=%s err=%v", pub, src, pkgDir, err)
		}
	}

	emitDriverProbeLogf(0, "[ExportByINFs] completed: destination=%s exported=%d", dst, okCnt)
	return okCnt, nil
}

// ExportDrivers 导出驱动包到 destination：
// - oemOnly=true：仅导出 OEM（第三方）
// - 导出策略：尽量定位到 DriverStore\FileRepository 中的真实 INF，然后复制整个驱动包目录；否则回退 INF 及关联文件。
func (m *DriverManager) ExportDrivers(destination string, oemOnly bool) (int, error) {
	if err := os.MkdirAll(destination, 0755); err != nil {
		log.LogWrite(-2, "[ExportDrivers]创建目录失败: dir=%s err=%v", destination, err)
		return 0, err
	}

	var drivers []DriverInfo
	var err error
	if oemOnly {
		drivers, err = m.EnumerateOEMDrivers()
	} else {
		drivers, err = m.EnumerateAllDrivers()
	}
	if err != nil {
		return 0, err
	}

	seen := map[string]struct{}{}
	okCount := 0

	for _, d := range drivers {
		key := strings.ToLower(filepath.Base(d.InfPath))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		storeInf := m.resolveDriverStoreInfPath(d.InfPath)
		if storeInf == "" {
			// 最后 fallback：Windows\INF\<oemXX.inf>
			storeInf = filepath.Join(filepath.Join(utils.WindowsDir(), "INF"), filepath.Base(d.InfPath))
		}
		if _, err := os.Stat(storeInf); err != nil {
			continue
		}

		infStem := strings.TrimSuffix(filepath.Base(d.InfPath), filepath.Ext(d.InfPath))
		dstDir := filepath.Join(destination, infStem)
		_ = os.MkdirAll(dstDir, 0755)

		if err := m.copyDriverPackage(storeInf, dstDir); err == nil {
			okCount++
		}
	}

	return okCount, nil
}

// resolveDriverStoreInfPath 尝试把 “oemXX.inf 或 infPath” 解析成 DriverStore\FileRepository 中的真实 INF 路径。
// - Win8+：优先 SetupGetInfDriverStoreLocationW
// - Win7：扫描 FileRepository 找同名 INF，再不行用 CatalogFile 推断目录
// - 再不行返回空，让上层去 Windows\INF 回退。
func (m *DriverManager) ExportDriversByClassGUID(destination string, classGUID string) (int, error) {
	if err := os.MkdirAll(destination, 0755); err != nil {
		log.LogWrite(-2, "[ExportDriversByClassGUID] 创建目录失败: dir=%s err=%v", destination, err)
		return 0, err
	}

	emitDriverProbeLogf(0, "[ExportDriversByClassGUID] start: guid=%s destination=%s", classGUID, destination)
	drivers, err := m.EnumerateDriversByClassGUID(classGUID)
	if err != nil {
		emitDriverProbeLogf(-2, "[ExportDriversByClassGUID] enumerate failed: guid=%s err=%v", classGUID, err)
		return 0, err
	}
	emitDriverProbeLogf(0, "[ExportDriversByClassGUID] enumerated: guid=%s drivers=%d destination=%s", classGUID, len(drivers), destination)

	seen := map[string]struct{}{}
	okCount := 0

	for idx, d := range drivers {
		emitDriverProbeLogf(
			0,
			"[ExportDriversByClassGUID] item[%d/%d]: guid=%s inf=%s classGuid=%s class=%s desc=%s",
			idx+1,
			len(drivers),
			classGUID,
			d.InfPath,
			d.ClassGUID,
			d.DeviceClass,
			d.Description,
		)
		key := strings.ToLower(filepath.Base(d.InfPath))
		if _, exists := seen[key]; exists {
			emitDriverProbeLogf(0, "[ExportDriversByClassGUID] skip duplicate: guid=%s inf=%s key=%s", classGUID, d.InfPath, key)
			continue
		}
		seen[key] = struct{}{}

		storeInf := m.resolveDriverStoreInfPath(d.InfPath)
		if storeInf == "" {
			emitDriverProbeLogf(0, "[ExportDriversByClassGUID] resolve store inf empty, fallback to Windows\\INF: guid=%s inf=%s", classGUID, d.InfPath)
			storeInf = filepath.Join(filepath.Join(utils.WindowsDir(), "INF"), filepath.Base(d.InfPath))
		} else {
			emitDriverProbeLogf(0, "[ExportDriversByClassGUID] resolved store inf: guid=%s inf=%s storeInf=%s", classGUID, d.InfPath, storeInf)
		}
		if _, err := os.Stat(storeInf); err != nil {
			emitDriverProbeLogf(-1, "[ExportDriversByClassGUID] skip missing source: guid=%s inf=%s storeInf=%s err=%v", classGUID, d.InfPath, storeInf, err)
			continue
		}

		infStem := strings.TrimSuffix(filepath.Base(d.InfPath), filepath.Ext(d.InfPath))
		dstDir := filepath.Join(destination, infStem)
		_ = os.MkdirAll(dstDir, 0755)
		emitDriverProbeLogf(0, "[ExportDriversByClassGUID] copy start: guid=%s source=%s dst=%s", classGUID, storeInf, dstDir)

		if copyErr := m.copyDriverPackage(storeInf, dstDir); copyErr == nil {
			okCount++
			infFiles, findErr := findInfFiles(dstDir)
			if findErr != nil {
				emitDriverProbeLogf(-1, "[ExportDriversByClassGUID] copy done but count inf failed: guid=%s dst=%s err=%v", classGUID, dstDir, findErr)
			}
			emitDriverProbeLogf(0, "[ExportDriversByClassGUID] copy done: guid=%s dst=%s infs=%d", classGUID, dstDir, len(infFiles))
		} else {
			emitDriverProbeLogf(-2, "[ExportDriversByClassGUID] copy failed: guid=%s source=%s dst=%s err=%v", classGUID, storeInf, dstDir, copyErr)
		}
	}

	emitDriverProbeLogf(0, "[ExportDriversByClassGUID] completed: guid=%s exported=%d enumerated=%d destination=%s", classGUID, okCount, len(drivers), destination)
	return okCount, nil
}

func (m *DriverManager) resolveDriverStoreInfPath(infNameOrPath string) string {
	if p, ok := m.setup.tryGetInfDriverStoreLocation(infNameOrPath); ok && p != "" {
		return p
	}

	base := strings.ToLower(filepath.Base(infNameOrPath))

	// ⚠️ GetSystem32Dir() 需要你在别处实现：WOW64 下应返回 Sysnative，否则 System32
	repo := filepath.Join(utils.GetSystem32Dir(), "DriverStore", "FileRepository")

	found := findFileInDriverStore(repo, base)
	if found != "" {
		return found
	}

	oemPath := filepath.Join(filepath.Join(utils.WindowsDir(), "INF"), filepath.Base(infNameOrPath))
	cat := parseCatalogFileFromINF(oemPath)
	if cat != "" {
		foundCat := findFileInDriverStore(repo, strings.ToLower(cat))
		if foundCat != "" {
			dir := filepath.Dir(foundCat)
			candidate := filepath.Join(dir, filepath.Base(infNameOrPath))
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
			if anyInf := firstInfInDir(dir); anyInf != "" {
				return anyInf
			}
		}
	}
	return ""
}

// findFileInDriverStore 在 DriverStore\FileRepository 的每个子目录根下查找指定文件名（lowerName）。
// 为了性能：只查一层（不递归深入）。
func findFileInDriverStore(repo string, lowerName string) string {
	entries, err := os.ReadDir(repo)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(repo, e.Name())
		items, _ := os.ReadDir(dir)
		for _, it := range items {
			if it.IsDir() {
				continue
			}
			if strings.ToLower(it.Name()) == lowerName {
				return filepath.Join(dir, it.Name())
			}
		}
	}
	return ""
}

// firstInfInDir 返回目录中找到的第一个 .inf 文件路径（找不到返回空）。
func firstInfInDir(dir string) string {
	items, _ := os.ReadDir(dir)
	for _, it := range items {
		if it.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(it.Name()), ".inf") {
			return filepath.Join(dir, it.Name())
		}
	}
	return ""
}

// parseCatalogFileFromINF 解析 INF 文本中的 CatalogFile=xxx.cat，返回 cat 文件名（不含路径）。
func parseCatalogFileFromINF(infPath string) string {
	f, err := os.Open(infPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "catalogfile") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val := strings.TrimSpace(parts[1])
			val = strings.SplitN(val, ";", 2)[0]
			val = strings.TrimSpace(val)
			val = strings.Trim(val, `"`)
			if val != "" {
				return val
			}
		}
	}
	return ""
}

// copyDriverPackage 把一个驱动“包”复制到目标目录：
// - 如果 INF 位于 FileRepository：复制整个目录（包含 sys/cat/dll 等）
// - 否则（Windows\INF 场景）：复制 INF + 尝试复制 INF 内提到的关联文件（简化策略）。
func (m *DriverManager) copyDriverPackage(infPath string, destDir string) error {
	parent := filepath.Dir(infPath)
	if strings.Contains(strings.ToLower(parent), "filerepository") {
		emitDriverProbeLogf(0, "[copyDriverPackage] copy repository dir: inf=%s srcDir=%s dstDir=%s", infPath, parent, destDir)
		return copyDirRecursive(parent, destDir)
	}

	dstInf := filepath.Join(destDir, filepath.Base(infPath))
	emitDriverProbeLogf(0, "[copyDriverPackage] copy fallback inf: inf=%s dstInf=%s", infPath, dstInf)
	if err := file.Copy(infPath, dstInf, true, true); err != nil {
		emitDriverProbeLogf(-2, "[copyDriverPackage] copy fallback inf failed: inf=%s dstInf=%s err=%v", infPath, dstInf, err)
		return err
	}
	if err := tryCopyAssociatedFiles(infPath, destDir); err != nil {
		emitDriverProbeLogf(-2, "[copyDriverPackage] copy associated files failed: inf=%s dstDir=%s err=%v", infPath, destDir, err)
		return err
	}
	emitDriverProbeLogf(0, "[copyDriverPackage] fallback package completed: inf=%s dstDir=%s", infPath, destDir)
	return nil
}

// copyDirRecursive 递归复制目录树：把 src 的内容完整复制到 dst。
func copyDirRecursive(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		sp := filepath.Join(src, e.Name())
		dp := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyDirRecursive(sp, dp); err != nil {
				return err
			}
		} else {
			if err := file.Copy(sp, dp, true, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// tryCopyAssociatedFiles 从 INF 文本里粗略扫描 .sys/.dll/.cat，然后去 System32\drivers 尝试复制到 destDir。
// 注意：这是“尽力而为”的简化逻辑，不保证覆盖 INF 里所有 CopyFiles/SourceDisksFiles 规则。
func tryCopyAssociatedFiles(infPath, destDir string) error {
	data, err := os.ReadFile(infPath)
	if err != nil {
		return err
	}

	// ⚠️ GetSystem32Dir() 需要你实现：WOW64 下应返回 Sysnative，否则 System32
	driversDir := filepath.Join(utils.GetSystem32Dir(), "drivers")

	lines := strings.Split(string(data), "\n")
	for _, ln := range lines {
		line := strings.TrimSpace(ln)
		low := strings.ToLower(line)
		if strings.HasSuffix(low, ".sys") || strings.HasSuffix(low, ".dll") || strings.HasSuffix(low, ".cat") {
			fileName := strings.TrimSpace(strings.SplitN(line, ",", 2)[0])
			fileName = strings.Trim(fileName, `"`)
			fileName = filepath.Base(fileName)

			src := filepath.Join(driversDir, fileName)
			if _, err := os.Stat(src); err == nil {
				_ = file.Copy(src, filepath.Join(destDir, fileName), true, true)
			}
		}
	}
	return nil
}

// ImportDrivers 在线导入/安装：递归扫描 sourceDir 下所有 .inf，然后逐个安装。
// - 优先用 newdev.dll 真安装
// - newdev 不可用或失败时回退 SetupCopyOEMInfW（仅入库）。
func (m *DriverManager) ImportDrivers(sourceDir string, force bool) (success, fail int, needReboot bool, err error) {
	infFiles, err := findInfFiles(sourceDir)
	if err != nil {
		return 0, 0, false, err
	}

	for _, inf := range infFiles {
		rb, e := m.installSingleDriver(inf, force)
		if e != nil {
			fail++
			continue
		}
		success++
		needReboot = needReboot || rb
	}
	return success, fail, needReboot, nil
}

// installSingleDriver 安装单个 INF：
// - 有 newdev 就调用 DiInstallDriverW
// - 失败则回退 SetupCopyOEMInfW（只入库，不保证设备绑定）。
func (m *DriverManager) installSingleDriver(infPath string, force bool) (bool, error) {
	if m.newdev != nil {
		if rb, err := m.newdev.installDriver(infPath, force); err == nil {
			return rb, nil
		}
	}
	_, err := m.setup.setupCopyOEMInf(infPath)
	return false, err
}

// findInfFiles 递归扫描目录，返回所有 .inf 文件路径列表。
func findInfFiles(dir string) ([]string, error) {
	var out []string
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".inf") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// ImportDriversOffline 离线导入：优先调用 DISM /Add-Driver；失败再走 legacy 方案（尽力写入 DriverStore/INF/Services）。
func (m *DriverManager) ImportDriversOffline(offlineRoot, sourceDir string) (success, fail int, err error) {
	infFiles, err := findInfFiles(sourceDir)
	if err != nil {
		return 0, 0, err
	}
	infCount := len(infFiles)
	if infCount == 0 {
		infCount = 1
	}

	if err := dismAddDrivers(offlineRoot, sourceDir); err == nil {
		return infCount, 0, nil
	}

	return m.importDriversOfflineLegacy(offlineRoot, sourceDir)
}

// dismAddDrivers 调用 dism.exe，把 sourceDir 下驱动递归加入离线镜像 offlineRoot。
func dismAddDrivers(offlineRoot, sourceDir string) error {
	args := []string{
		"/Image:" + offlineRoot,
		"/Add-Driver",
		"/Driver:" + sourceDir,
		"/Recurse",
	}
	cmd := exec.Command(dism, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// importDriversOfflineLegacy legacy 离线导入：
// - 复制驱动目录到离线 DriverStore\FileRepository
// - 把 .sys 复制到离线 System32\drivers
// - 生成 oemN.inf
// - 尝试写离线 SYSTEM hive 的 Services（失败不算 fail）。
func (m *DriverManager) importDriversOfflineLegacy(offlineRoot, sourceDir string) (success, fail int, err error) {
	driverStore := filepath.Join(offlineRoot, "Windows", "System32", "DriverStore", "FileRepository")
	systemDrivers := filepath.Join(offlineRoot, "Windows", "System32", "drivers")
	infDir := filepath.Join(offlineRoot, "Windows", "INF")

	_ = os.MkdirAll(driverStore, 0755)
	_ = os.MkdirAll(systemDrivers, 0755)
	_ = os.MkdirAll(infDir, 0755)

	oemIndex := getNextOEMIndex(infDir)

	infFiles, err := findInfFiles(sourceDir)
	if err != nil {
		return 0, 0, err
	}

	for _, inf := range infFiles {
		infSourceDir := filepath.Dir(inf)
		infStem := strings.TrimSuffix(filepath.Base(inf), filepath.Ext(inf))
		infFilename := filepath.Base(inf)

		targetStoreDir := filepath.Join(driverStore, fmt.Sprintf("%s.inf_amd64_offline%08x", infStem, oemIndex))
		if err := copyDirRecursive(infSourceDir, targetStoreDir); err != nil {
			fail++
			continue
		}

		_ = copySysFilesToDrivers(targetStoreDir, systemDrivers)

		oemInfName := fmt.Sprintf("oem%d.inf", oemIndex)
		oemInfPath := filepath.Join(infDir, oemInfName)
		sourceInf := filepath.Join(targetStoreDir, infFilename)
		if _, err := os.Stat(sourceInf); err == nil {
			_ = file.Copy(sourceInf, oemInfPath, true, true)
		}

		_ = registerDriverServicesOffline(offlineRoot, targetStoreDir, infFilename, oemInfName)

		success++
		oemIndex++
	}

	return success, fail, nil
}

// getNextOEMIndex 扫描离线 INF 目录下已有 oem*.inf，返回下一个可用序号（max+1）。
func getNextOEMIndex(infDir string) uint32 {
	var max uint32
	entries, err := os.ReadDir(infDir)
	if err != nil {
		return 1
	}
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, "oem") && strings.HasSuffix(n, ".inf") {
			num := strings.TrimSuffix(strings.TrimPrefix(n, "oem"), ".inf")
			var v uint32
			_, _ = fmt.Sscanf(num, "%d", &v)
			if v > max {
				max = v
			}
		}
	}
	return max + 1
}

// copySysFilesToDrivers 在某个 storeDir 里找 .sys 文件，复制到离线 driversDir（存在则跳过）。
func copySysFilesToDrivers(storeDir, driversDir string) error {
	entries, err := os.ReadDir(storeDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(e.Name()), ".sys") {
			src := filepath.Join(storeDir, e.Name())
			dst := filepath.Join(driversDir, e.Name())
			if _, err := os.Stat(dst); err == nil {
				continue
			}
			_ = file.Copy(src, dst, true, true)
		}
	}
	return nil
}

// registerDriverServicesOffline 把 INF 中解析出来的服务信息写入离线 SYSTEM hive（ControlSet001/002）。
// - 需要 RegLoadKey 权限；失败直接跳过（返回 nil，表示“不阻塞”）。
func registerDriverServicesOffline(offlineRoot, driverStoreDir, infFilename, oemInfName string) error {
	infPath := filepath.Join(driverStoreDir, infFilename)
	b, err := os.ReadFile(infPath)
	if err != nil {
		return nil
	}
	services := parseInfServiceInfo(string(b))
	if len(services) == 0 {
		return nil
	}

	systemHive := filepath.Join(offlineRoot, "Windows", "System32", "config", "SYSTEM")
	if _, err := os.Stat(systemHive); err != nil {
		return nil
	}

	hiveName := fmt.Sprintf("drv_offline_%d", os.Getpid())

	if err := regLoadHiveLocalMachine(hiveName, systemHive); err != nil {
		return nil
	}
	defer regUnloadHiveLocalMachine(hiveName)

	for _, s := range services {
		writeServiceToControlSets(hiveName, s)
	}
	return nil
}

// regLoadHiveLocalMachine 调用 RegLoadKeyW，把离线 hive 挂载到 HKLM\<mountName>。
func regLoadHiveLocalMachine(mountName, hivePath string) error {
	adv := windows.NewLazySystemDLL("advapi32.dll")
	pLoad := adv.NewProc("RegLoadKeyW")
	if err := adv.Load(); err != nil {
		return err
	}

	sub, _ := windows.UTF16PtrFromString(mountName)
	hive, _ := windows.UTF16PtrFromString(hivePath)
	r1, _, e1 := pLoad.Call(
		uintptr(registry.LOCAL_MACHINE),
		uintptr(unsafe.Pointer(sub)),
		uintptr(unsafe.Pointer(hive)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// regUnloadHiveLocalMachine 调用 RegUnLoadKeyW 卸载 HKLM\<mountName>（失败忽略）。
func regUnloadHiveLocalMachine(mountName string) {
	adv := windows.NewLazySystemDLL("advapi32.dll")
	pUnload := adv.NewProc("RegUnLoadKeyW")
	if err := adv.Load(); err != nil {
		return
	}
	sub, _ := windows.UTF16PtrFromString(mountName)
	_, _, _ = pUnload.Call(uintptr(registry.LOCAL_MACHINE), uintptr(unsafe.Pointer(sub)))
}

// infService 表示从 INF 解析出来的一个 Service 配置项（离线写注册表用）。
type infService struct {
	Name         string
	Binary       string
	ServiceType  uint32
	StartType    uint32
	ErrorControl uint32
}

// writeServiceToControlSets 把一个 service 写入离线 hive 的 ControlSet001/002\Services\<Name>。
func writeServiceToControlSets(hiveName string, s infService) {
	paths := []string{
		fmt.Sprintf(`%s\ControlSet001\Services\%s`, hiveName, s.Name),
		fmt.Sprintf(`%s\ControlSet002\Services\%s`, hiveName, s.Name),
	}
	for _, p := range paths {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, p, registry.SET_VALUE)
		if err != nil {
			continue
		}
		_ = k.SetDWordValue("Type", s.ServiceType)
		_ = k.SetDWordValue("Start", s.StartType)
		_ = k.SetDWordValue("ErrorControl", s.ErrorControl)

		img := s.Binary
		if !strings.Contains(img, `\`) && !strings.Contains(img, `/`) {
			img = `System32\drivers\` + img
		}
		_ = k.SetExpandStringValue("ImagePath", img)
		_ = k.Close()
	}
}

// parseInfServiceInfo 解析 INF 文件内容中的 AddService / ServiceInstallSection，提取服务名、二进制、类型、启动方式等。
// 这是简化解析：只处理常见键：ServiceType/StartType/ErrorControl/ServiceBinary。
func parseInfServiceInfo(content string) []infService {
	lines := strings.Split(content, "\n")

	current := ""
	installSecToSvc := map[string]string{}

	// pass1：AddService => installSection -> serviceName
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			_ = current
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "addservice") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			args := splitCSV(parts[1])
			if len(args) >= 3 {
				svc := strings.TrimSpace(args[0])
				sec := strings.ToLower(strings.TrimSpace(args[2]))
				if svc != "" && sec != "" {
					installSecToSvc[sec] = svc
				}
			}
		}
	}

	// pass2：解析 service install sections
	var out []infService
	current = ""
	st := uint32(OFFLINE_SERVICE_TYPE_DEFAULT)
	start := uint32(OFFLINE_START_TYPE_DEFAULT)
	errCtl := uint32(OFFLINE_ERROR_CONTROL_DEFAULT)
	bin := ""

	flush := func(sec string) {
		if svc, ok := installSecToSvc[sec]; ok {
			if strings.TrimSpace(bin) != "" {
				out = append(out, infService{
					Name:         svc,
					Binary:       bin,
					ServiceType:  st,
					StartType:    start,
					ErrorControl: errCtl,
				})
			}
		}
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush(current)

			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			st = OFFLINE_SERVICE_TYPE_DEFAULT
			start = OFFLINE_START_TYPE_DEFAULT
			errCtl = OFFLINE_ERROR_CONTROL_DEFAULT
			bin = ""
			continue
		}

		if _, ok := installSecToSvc[current]; !ok {
			continue
		}

		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		val = strings.SplitN(val, ";", 2)[0]
		val = strings.SplitN(val, ",", 2)[0]
		val = strings.TrimSpace(val)

		switch key {
		case "servicetype":
			st = parseInfNumber(val)
		case "starttype":
			start = parseInfNumber(val)
		case "errorcontrol":
			errCtl = parseInfNumber(val)
		case "servicebinary":
			bin = resolveInfPath(val)
		}
	}
	flush(current)

	return out
}

// splitCSV 按逗号分割并 TrimSpace，用于解析 AddService 的参数列表（简化版）。
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// parseInfNumber 解析 INF 里常见数字格式：支持 0xNN 或十进制 NN。
func parseInfNumber(v string) uint32 {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	low := strings.ToLower(v)
	if strings.HasPrefix(low, "0x") {
		var x uint32
		_, _ = fmt.Sscanf(low[2:], "%x", &x)
		return x
	}
	var d uint32
	_, _ = fmt.Sscanf(low, "%d", &d)
	return d
}

// resolveInfPath 简化解析 INF 里的路径字段：
// - 去掉引号
// - 把 %12%\xxx.sys、a\b\c.sys 等路径只取最后的文件名。
func resolveInfPath(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	v = strings.ReplaceAll(v, "/", `\`)
	if i := strings.LastIndex(v, `\`); i >= 0 {
		v = v[i+1:]
	}
	return strings.TrimSpace(v)
}

// ExportDrivers 对外导出：默认只导出 OEM 驱动。
func ExportDrivers(destination string) (int, error) {
	m, err := NewDriverManager()
	if err != nil {
		return 0, err
	}
	return m.ExportDrivers(destination, true)
}

// ExportByINFs 创建驱动管理器后执行按发布 INF 名导出。
func ExportByINFs(dst string, pats []string) (int, error) {
	emitDriverProbeLogf(0, "[ExportByINFs] wrapper start: destination=%s patterns=%v", dst, pats)
	m, err := NewDriverManager()
	if err != nil {
		emitDriverProbeLogf(-2, "[ExportByINFs] create manager failed: err=%v", err)
		return 0, err
	}
	return m.ExportByINFs(dst, pats)
}

// ExportDriversFromSystem 从“另一个系统分区”(PE 场景)导出第三方驱动目录：
// 直接遍历 <systemPartition>\Windows\System32\DriverStore\FileRepository。
func ExportDriversFromSystem(systemPartition, destination string) (int, error) {
	srcRepo := filepath.Join(systemPartition, "Windows", "System32", "DriverStore", "FileRepository")
	if _, err := os.Stat(srcRepo); err != nil {
		return 0, fmt.Errorf("driver store not found: %s", srcRepo)
	}
	_ = os.MkdirAll(destination, 0755)

	ok := 0
	entries, err := os.ReadDir(srcRepo)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if isThirdPartyDriverDir(name) {
			if err := copyDirRecursive(filepath.Join(srcRepo, name), filepath.Join(destination, name)); err == nil {
				ok++
			}
		}
	}
	return ok, nil
}

// ImportDrivers 对外在线导入：安装 sourceDir 下所有 INF。
func ImportDrivers(driverPath string, force bool) (success, fail int, needReboot bool, err error) {
	m, err := NewDriverManager()
	if err != nil {
		return 0, 0, false, err
	}
	return m.ImportDrivers(driverPath, force)
}

// ImportDriversOffline 对外离线导入：把 sourceDir 的驱动注入 offlineRoot。
func ImportDriversOffline(offlineRoot, driverPath string) (success, fail int, err error) {
	m, err := NewDriverManager()
	if err != nil {
		return 0, 0, err
	}
	return m.ImportDriversOffline(offlineRoot, driverPath)
}

// ListOEMDrivers 对外：列出在线系统 OEM 驱动信息（oemXX.inf）。
func ListOEMDrivers() ([]DriverInfo, error) {
	m, err := NewDriverManager()
	if err != nil {
		return nil, err
	}
	return m.EnumerateOEMDrivers()
}

// ListAllDrivers 对外：列出在线系统所有设备关联驱动信息。
func ListAllDrivers() ([]DriverInfo, error) {
	m, err := NewDriverManager()
	if err != nil {
		return nil, err
	}
	return m.EnumerateAllDrivers()
}

func ListDriversByClassGUID(classGUID string) ([]DriverInfo, error) {
	m, err := NewDriverManager()
	if err != nil {
		return nil, err
	}
	return m.EnumerateDriversByClassGUID(classGUID)
}

// isThirdPartyDriverDir 用目录名粗略判断 DriverStore\FileRepository 下是否为第三方驱动目录。
// 规则：包含 oem 认为是第三方；对一些常见系统前缀返回 false；其它默认 true。
func ExportDriversByClassGUID(destination string, classGUID string) (int, error) {
	emitDriverProbeLogf(0, "[ExportDriversByClassGUID] wrapper start: destination=%s guid=%s", destination, classGUID)
	m, err := NewDriverManager()
	if err != nil {
		emitDriverProbeLogf(-2, "[ExportDriversByClassGUID] create manager failed: guid=%s err=%v", classGUID, err)
		return 0, err
	}
	return m.ExportDriversByClassGUID(destination, classGUID)
}

func isThirdPartyDriverDir(dirName string) bool {
	lower := strings.ToLower(dirName)
	if strings.Contains(lower, "oem") {
		return true
	}
	systemPrefixes := []string{
		"acpi", "basicdisplay", "disk", "hid", "usb", "pci", "ntfs", "wdf", "wmilib", "volmgr",
	}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(lower, p) {
			return false
		}
	}
	return true
}
