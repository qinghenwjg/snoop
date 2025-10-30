package data

import (
	"bufio"
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type ProcessLine struct {
	ppid int32
	line string
}

type ProcessLineMap struct {
	m     map[int32]ProcessLine
	mutex *sync.RWMutex
}

// 维护进程链信息
var LineMap = &ProcessLineMap{
	m:     map[int32]ProcessLine{},
	mutex: &sync.RWMutex{},
}

func (l *ProcessLineMap) WriteProcessLineMap(pid int32, ppid int32, line string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.m[pid] = ProcessLine{ppid: ppid, line: line}
}

func (l *ProcessLineMap) DeleteProcessLineMap(pid int32) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	delete(l.m, pid)
}

func (l *ProcessLineMap) GetProcessLine(pid int32) ProcessLine {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return LineMap.m[pid]
}

// 存在返回true，不存在返回false
func (l *ProcessLineMap) IsExist(pid int32) bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return LineMap.m[pid] != ProcessLine{}
}

// 获取当前时刻，所有进程的信息，并存储到map中
// 在程序一开始启动时执行
func InitLineMap() {
	//LineMap = map[int32]ProcessLine{} //清空旧信息
	// 执行 ps -eLf 命令
	cmd := exec.Command("sh", "-c", "sudo ps -eLf")
	output, err := cmd.Output()
	if err != nil {
		log.Println("Error executing command:", err)
		return
	}

	// 创建一个扫描器来逐行读取命令输出
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	// 跳过标题行
	if scanner.Scan() {
		// 读取第一行（标题行）
	}

	// 逐行解析输出
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			// 如果字段数量少于预期，跳过该行
			continue
		}
		ppid, _ := strconv.Atoi(fields[2])   // PPID是第三个字段
		lwp, _ := strconv.Atoi(fields[3])    // LWP是第四个字段
		cmd := strings.Join(fields[9:], " ") // CMD是第9列之后的字段

		// 输出提取的信息
		LineMap.WriteProcessLineMap(int32(lwp), int32(ppid), cmd)
	}

	// 检查是否在扫描过程中发生错误
	if err := scanner.Err(); err != nil {
		log.Println("Error reading command output:", err)
	}
}

func (l *ProcessLineMap) GetProcessLineById(pid int32) []byte {
	tmpLines := []map[int32]string{}
	for {
		v := LineMap.GetProcessLine(pid)
		tmpLines = append(tmpLines, map[int32]string{pid: v.line})
		pid = v.ppid
		if pid == 0 { // 递归到了进程链顶端
			break
		}
	}
	ProcLine, _ := json.Marshal(tmpLines)
	return ProcLine
}
