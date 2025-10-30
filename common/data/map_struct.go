package data

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ProcMap struct {
	m     map[string]ProcRecord
	mutex *sync.RWMutex
}

func (m *ProcMap) Write(r ProcRecord) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.GetFileRecord(&r)

	if _, ok := m.m[r.Argv]; !ok {
		r.LogTime = time.Now().Format("2006-01-02 15:04:05")
		r.Line = LineMap.GetProcessLineById(r.Pid)
		//根据uid获取用户名
		usr, _ := user.LookupId(fmt.Sprintf("%d", r.Uid))
		r.UserName = usr.Username
		m.m[r.Argv] = r
	}
}

func (m *ProcMap) GetSlsData() map[string]ProcRecord {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	tmpMap := m.m
	m.m = map[string]ProcRecord{}
	return tmpMap
}

var MyProcMap = ProcMap{
	m:     map[string]ProcRecord{},
	mutex: &sync.RWMutex{},
}

func (m *ProcMap) GetFileRecord(r *ProcRecord) {
	// 去重前提取文件信息, 先获取文件路径
	if r.Pwd != "" {
		pwds := strings.Split(strings.TrimSpace(r.Pwd), " ")
		pwd := ""
		for i := len(pwds) - 1; i >= 0; i-- {
			if pwds[i] == "/" {
				continue
			}
			pwd += "/" + pwds[i]
		}
		if pwd == "" {
			pwd = "/"
		}
		r.Pwd = pwd
	}
	// 相对路径转绝对路径
	if len(r.Path) > 0 && r.Path[0] != '/' {
		r.Path = r.Pwd + "/" + r.Path
	}
	r.Path, _ = filepath.Abs(r.Path)
	if r.Path == "" {
		fmt.Println(*r)
	}
	go getFilePath(r) //文件处理，比较耗时，单独开一个goroutine，不block进程信息的处理
}

func getFilePath(rec *ProcRecord) {

	MyFileMap.Write(&FileRecord{
		Pid:      rec.Pid,
		Path:     rec.Path,
		FileType: "binary",
		CmdLine:  rec.Argv,
		LogTime:  rec.LogTime,
	})
	pattern := `(/bin/bash|/bin/sh|/bin/python|/bin/java)` // 也能匹配python2.7之类的二进制
	filePattern := `\.(sh|py|jar)$`

	re := regexp.MustCompile(pattern)
	refile := regexp.MustCompile(filePattern)

	if re.MatchString(rec.Path) {
		args := strings.Split(rec.Argv, " ")
		for _, v := range args {
			if refile.MatchString(v) {
				var scriptPath string
				if path.IsAbs(v) {
					scriptPath = v
				} else {
					scriptPath, _ = filepath.Abs(rec.Pwd + "/" + v)
				}
				MyFileMap.Write(&FileRecord{
					Pid:      rec.Pid,
					Path:     scriptPath,
					FileType: GetFileType(v),
					CmdLine:  rec.Argv,
					LogTime:  rec.LogTime,
				})
			}
		}
	}
}

// 根据文件的后缀，获取文件的类型
var FileTypeMap = map[string]string{"sh": "shell", "py": "python", "jar": "java"}

func GetFileType(str string) string {
	idx := strings.LastIndex(str, ".")
	if idx < 0 {
		return "unknown"
	}
	str = str[idx+1:]
	return FileTypeMap[str]
}

//------------------------------------------------------------------------------//

type NetMap struct {
	m     map[string]NetRecord
	mutex *sync.RWMutex
}

var MyNetMap = NetMap{
	m:     map[string]NetRecord{},
	mutex: &sync.RWMutex{},
}

// 写入的时候即开始去重，根据socket字段进行去重
func (m *NetMap) Write(r *NetRecord) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, ok := m.m[r.Socket]; !ok {
		r.Line = LineMap.GetProcessLineById(r.Pid)
		m.m[r.Socket] = *r
	}
}

// 获取可以投递到SLS的日志数据，并清空原有的数据
func (m *NetMap) GetSlsData() map[string]NetRecord {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var tmpMap = m.m
	m.m = map[string]NetRecord{}
	return tmpMap
}

//------------------------------------------------------------------------------//

type FileMap struct {
	m     map[string]FileRecord
	mutex *sync.RWMutex
}

var MyFileMap = FileMap{
	m:     map[string]FileRecord{},
	mutex: &sync.RWMutex{},
}

// 根据文件名和修改时间去重。
func (m *FileMap) Write(r *FileRecord) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	formatFileMessage(r)
	r.UniqueId = r.Path + " " + r.ModifyTime.String()
	if _, ok := m.m[r.UniqueId]; !ok { //去重，去完重之后，再计算MD5值并保存到Map中
		r.MD5, _ = FileMD5(r.Path)
		// if r.MD5 != "" && r.FileSize < OSSFileLimit && r.FileSize > 0 {
		// 	oss.PutOSSObject(oss.DefaultBucketName, r.Path, r.MD5)
		// }
		m.m[r.UniqueId] = *r
	}
}

func (m *FileMap) GetSlsData() map[string]FileRecord {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	tmpMap := m.m
	m.m = map[string]FileRecord{}
	return tmpMap
}

func FileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	hash := md5.New()
	_, _ = io.Copy(hash, file)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func formatFileMessage(rec *FileRecord) {
	f, err := os.Stat(rec.Path)
	if err != nil { //文件状态异常，则返回
		return
	}
	rec.FileSize = f.Size()
	fileAttr := f.Sys().(*syscall.Stat_t)
	rec.ChangeTime = SecondToTime(fileAttr.Ctim.Sec)
	rec.AccessTime = SecondToTime(fileAttr.Atim.Sec)
	rec.ModifyTime = SecondToTime(fileAttr.Mtim.Sec)
}

func SecondToTime(sec int64) time.Time {
	return time.Unix(sec, 0)
}
