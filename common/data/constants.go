package data

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

var SysBootTime, _ = getSystemBootTime()

const (
	LocalAddr    = "127.0.0.1"
	OSSFileLimit = 30 * 1024 * 1024 //30MB
	Nanosecond   = 1000000000
)

// 获取系统启动时间，单位是纳秒
func getSystemBootTime() (int64, error) {
	f, err := os.Open("/proc/uptime")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
			if err != nil {
				return 0, err
			}
			return time.Now().UnixNano() - int64(uptimeSeconds*math.Pow10(9)), nil
		}
	}
	return 0, fmt.Errorf("unable to parse uptime")
}
