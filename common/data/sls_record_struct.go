package data

import "time"

type NetRecord struct {
	ProcRecord //结构体内嵌
	Sip        string
	Dip        string
	Sport      uint16
	Dport      uint16
	Proto      string
	Direct     string
	Socket     string
}

type FileRecord struct {
	UniqueId   string
	Pid        int32
	Path       string
	MD5        string
	FileType   string
	FileSize   int64
	CmdLine    string
	LogTime    string
	AccessTime time.Time
	ChangeTime time.Time
	ModifyTime time.Time
}

type ProcRecord struct {
	UserName string

	//进程通用字段
	Pid       int32
	Uid       uint32
	Cpuid     uint32
	Ppid      int32
	Sid       uint32
	Comm      string
	Path      string
	Argv      string   // 进程根据argv来进行去重，相同参数的进程，只保留一个。
	Args      []string // 第二个参数，部分情况下是python文件或者shell脚本
	Pwd       string
	Line      []byte
	LogTime   string
	StartTime string
}
