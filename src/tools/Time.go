package tools

import (
	"ReSys/src/log"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// NTP epoch starts at 1900-01-01 00:00:00 UTC
const ntpEpochOffset uint64 = 2208988800

var ntpServers = []string{
	"ntp.aliyun.com:123",
	"ntp.tencent.com:123",
	"cn.ntp.org.cn:123",
	"time.windows.com:123",
	"pool.ntp.org:123",
}

// Windows API: SetSystemTime expects UTC time.
type SYSTEMTIME struct {
	wYear         uint16
	wMonth        uint16
	wDayOfWeek    uint16 // 0=Sunday
	wDay          uint16
	wHour         uint16
	wMinute       uint16
	wSecond       uint16
	wMilliseconds uint16
}

var (
	Kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procSetSystemTime = Kernel32.NewProc("SetSystemTime")
)

// queryNTP 发送 NTP 请求并解析响应，返回服务器时间（UTC）。timeout 包括 DNS 解析时间。
func queryNTP(serverAddr string, timeout time.Duration) (time.Time, error) {
	// Use context timeout to also bound DNS resolution time.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		log.LogWrite(-1, "[queryNTP]连接NTP失败: server=%s err=%v", serverAddr, err)
		return time.Time{}, fmt.Errorf("dial udp %s failed: %w", serverAddr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Minimal NTP request: 48 bytes, first byte = LI(0)|VN(4)|Mode(3) => 0x23
	req := make([]byte, 48)
	req[0] = 0x23

	if _, err := conn.Write(req); err != nil {
		log.LogWrite(-1, "[queryNTP]发送NTP请求失败: server=%s err=%v", serverAddr, err)
		return time.Time{}, fmt.Errorf("send ntp request failed: %w", err)
	}

	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	if err != nil {
		log.LogWrite(-1, "[queryNTP]读取NTP响应失败: server=%s err=%v", serverAddr, err)
		return time.Time{}, fmt.Errorf("read ntp response failed: %w", err)
	}
	if n < 48 {
		log.LogWrite(-1, "[queryNTP]NTP响应长度异常: server=%s len=%d", serverAddr, n)
		return time.Time{}, fmt.Errorf("ntp response too short: %d", n)
	}

	// Transmit Timestamp starts at byte 40:
	// 40..43 seconds (big-endian), 44..47 fraction (big-endian)
	sec := uint64(binary.BigEndian.Uint32(resp[40:44]))
	frac := uint64(binary.BigEndian.Uint32(resp[44:48]))

	if sec < ntpEpochOffset {
		log.LogWrite(-1, "[queryNTP]NTP秒值异常: server=%s sec=%d", serverAddr, sec)
		return time.Time{}, fmt.Errorf("invalid ntp seconds: %d", sec)
	}

	unixSec := int64(sec - ntpEpochOffset)

	// fraction is fractional seconds in units of 2^-32
	// nanos = frac * 1e9 / 2^32  (use shift for /2^32)
	nanos := int64((frac * 1_000_000_000) >> 32)

	return time.Unix(unixSec, nanos).UTC(), nil
}

// 设置系统时间，参数t必须是UTC时间
func setSystemTimeUTC(t time.Time) error {
	utc := t.UTC()
	st := SYSTEMTIME{
		wYear:         uint16(utc.Year()),
		wMonth:        uint16(utc.Month()),
		wDay:          uint16(utc.Day()),
		wDayOfWeek:    uint16(utc.Weekday()), // Go: Sunday=0 matches Windows
		wHour:         uint16(utc.Hour()),
		wMinute:       uint16(utc.Minute()),
		wSecond:       uint16(utc.Second()),
		wMilliseconds: uint16(utc.Nanosecond() / 1e6),
	}

	r1, _, e1 := procSetSystemTime.Call(uintptr(unsafe.Pointer(&st)))
	if r1 == 0 {
		// e1 is syscall.Errno
		if e1 != nil && e1 != syscall.Errno(0) {
			log.LogWrite(-2, "[setSystemTimeUTC]设置系统时间失败: err=%v", e1)
			return fmt.Errorf("SetSystemTime failed: %w (try running as Administrator)", e1)
		}
		log.LogWrite(-2, "[setSystemTimeUTC]设置系统时间失败: unknown error")
		return errors.New("SetSystemTime failed: unknown error (try running as Administrator)")
	}
	return nil
}

type TimeSyncResult struct {
	Success bool
	Message string
	OldTime string
	NewTime string
	Server  string
}

// 同步时间
func SyncTime() TimeSyncResult {
	old := time.Now().Format("2006-01-02 15:04:05.000 MST")

	var lastErr error
	for _, server := range ntpServers {
		utcTime, err := queryNTP(server, 3*time.Second)
		if err != nil {
			log.LogWrite(-1, "[SyncTime]NTP服务器不可用: server=%s err=%v", server, err)
			lastErr = err
			continue
		}
		if err := setSystemTimeUTC(utcTime); err != nil {
			log.LogWrite(-2, "[SyncTime]同步时间失败: server=%s err=%v", server, err)
			return TimeSyncResult{
				Success: false,
				Message: fmt.Sprintf("got UTC from %s but setting system time failed: %v", server, err),
				OldTime: old,
				NewTime: "",
				Server:  server,
			}
		}

		newT := time.Now().Format("2006-01-02 15:04:05.000 MST")
		log.LogWrite(0, "[SyncTime]时间同步成功: server=%s old=%s new=%s", server, old, newT)
		return TimeSyncResult{
			Success: true,
			Message: fmt.Sprintf("time sync success (UTC via %s, SetSystemTime)", server),
			OldTime: old,
			NewTime: newT,
			Server:  server,
		}
	}

	msg := "unable to reach any NTP server"
	if lastErr != nil {
		msg = fmt.Sprintf("%s; last error: %v", msg, lastErr)
	}
	log.LogWrite(-2, "[SyncTime]时间同步失败: %s", msg)
	return TimeSyncResult{
		Success: false,
		Message: msg,
		OldTime: old,
		NewTime: "",
		Server:  "",
	}
}
