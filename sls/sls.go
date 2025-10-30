package sls

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"snoop/common/data"
	"snoop/utils"
	"strings"
	"time"

	aliyunsls "github.com/aliyun/aliyun-log-go-sdk"
	"google.golang.org/protobuf/proto"
)

// SlsStorage is the struct of the sls
type SlsStorage struct {
	ProjectName string
	LogStore    string
	Endpoint    string
	AccessKey   string
	SecretKey   string
	Client      aliyunsls.ClientInterface
}

var ProcSls, NetWorkSls, FileSls *SlsStorage

const (
	SlsEndpoint = "http://cn-hangzhou.log.aliyuncs.com" //内网域名：http://cn-hangzhou-intranet.log.aliyuncs.com
	SlsProject  = "ecs-sre-nc-metric"

	//加密后的AK和SK
	SlsAccessKey = "QcJSWk9ccclPY2n/ogS+jY/5lA/RVb/UX1lTJNSSt5c="
	SlsSecretKey = "tVo+sA7i/QfM3q9iJHc/aIfgn1URts1hbrjJDc/ZuTM="
)

// 返回值第一个是主机名，第二个是主机IP地址，第三个是错误
func GetLocalHostIpAndName() (string, string, error) {
	// from socket get local ip
	name, err := os.Hostname()
	if err != nil {
		return "", "", err
	}

	addr, err := net.LookupIP(name)
	if err != nil {
		return name, "", err
	}

	addrStr := addr[0].String()
	return name, addrStr, nil
}

func GetVMInstanceList() []string {
	cmd := exec.Command("virsh", "list")

	// 运行命令并捕获输出
	output, err := cmd.Output()
	if err != nil {
		//fmt.Println("Error executing virsh list:", err)
		return nil
	}

	var vmNames = []string{}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	headerSkipped := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过表头和空行
		if !headerSkipped {
			headerSkipped = true
			continue
		}
		if len(line) == 0 {
			continue
		}

		// 分割每行内容，默认格式为: Id 名称 状态
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			vmNames = append(vmNames, fields[1])
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading output:", err)
	}
	return vmNames
}

func init() {
	ak := utils.AesDecryptByECB(SlsAccessKey, utils.CustomKey)
	sk := utils.AesDecryptByECB(SlsSecretKey, utils.CustomKey)
	ProcSls = &SlsStorage{
		Endpoint:    SlsEndpoint,
		ProjectName: SlsProject,
		LogStore:    "ebpf_process",
		AccessKey:   ak,
		SecretKey:   sk,
	}
	ProcSls.Client = aliyunsls.CreateNormalInterfaceV2(ProcSls.Endpoint, aliyunsls.NewStaticCredentialsProvider(ProcSls.AccessKey, ProcSls.SecretKey, ""))
	NetWorkSls = &SlsStorage{
		Endpoint:    SlsEndpoint,
		ProjectName: SlsProject,
		LogStore:    "ebpf_network",
		AccessKey:   ak,
		SecretKey:   sk,
	}
	NetWorkSls.Client = aliyunsls.CreateNormalInterfaceV2(NetWorkSls.Endpoint, aliyunsls.NewStaticCredentialsProvider(NetWorkSls.AccessKey, NetWorkSls.SecretKey, ""))

	FileSls = &SlsStorage{
		Endpoint:    SlsEndpoint,
		ProjectName: SlsProject,
		LogStore:    "ebpf_file",
		AccessKey:   ak,
		SecretKey:   sk,
	}
	FileSls.Client = aliyunsls.CreateNormalInterfaceV2(FileSls.Endpoint, aliyunsls.NewStaticCredentialsProvider(FileSls.AccessKey, FileSls.SecretKey, ""))
}

func InsertProcRows(rows map[string]data.ProcRecord) error {
	logs := []*aliyunsls.Log{}
	localName, localIp, _ := GetLocalHostIpAndName()
	for _, row := range rows {
		content := []*aliyunsls.LogContent{}
		content = append(content,
			&aliyunsls.LogContent{Key: proto.String("pid"), Value: proto.String(fmt.Sprintf("%d", row.Pid))},
			&aliyunsls.LogContent{Key: proto.String("session_id"), Value: proto.String(fmt.Sprintf("%d", row.Sid))},
			&aliyunsls.LogContent{Key: proto.String("hostip"), Value: proto.String(localIp)},
			&aliyunsls.LogContent{Key: proto.String("hostname"), Value: proto.String(localName)},
			//&aliyunsls.LogContent{Key: proto.String("instance_id"), Value: proto.String(strings.Join(GetVMInstanceList(), ","))},
			&aliyunsls.LogContent{Key: proto.String("logtime"), Value: proto.String(row.LogTime)},
			&aliyunsls.LogContent{Key: proto.String("ppid"), Value: proto.String(fmt.Sprintf("%d", row.Ppid))},
			&aliyunsls.LogContent{Key: proto.String("uid"), Value: proto.String(fmt.Sprintf("%d", row.Uid))},
			&aliyunsls.LogContent{Key: proto.String("username"), Value: proto.String(row.UserName)},
			&aliyunsls.LogContent{Key: proto.String("cpuid"), Value: proto.String(fmt.Sprintf("%d", row.Cpuid))},
			&aliyunsls.LogContent{Key: proto.String("task"), Value: proto.String(row.Comm)},
			&aliyunsls.LogContent{Key: proto.String("file_path"), Value: proto.String(row.Path)},
			&aliyunsls.LogContent{Key: proto.String("file_name"), Value: proto.String(filepath.Base(row.Path))},
			&aliyunsls.LogContent{Key: proto.String("cmdline"), Value: proto.String(row.Argv)},
			&aliyunsls.LogContent{Key: proto.String("cwd"), Value: proto.String(row.Pwd)},
			&aliyunsls.LogContent{Key: proto.String("process_line"), Value: proto.String(string(row.Line))},
			&aliyunsls.LogContent{Key: proto.String("start_time"), Value: proto.String(string(row.StartTime))},
		)
		now := uint32(time.Now().Unix())
		logs = append(logs, &aliyunsls.Log{Time: &now, Contents: content})
	}

	loggroup := &aliyunsls.LogGroup{
		Topic:  proto.String("horus-process-monitor"),
		Source: proto.String(localIp),
		Logs:   logs,
	}
	return ProcSls.Client.PutLogs(ProcSls.ProjectName, ProcSls.LogStore, loggroup)
}

func InsertNetWorkRows(rows map[string]data.NetRecord) error {
	logs := []*aliyunsls.Log{}
	localName, localIp, _ := GetLocalHostIpAndName()

	for _, row := range rows {
		content := []*aliyunsls.LogContent{}
		content = append(content,
			&aliyunsls.LogContent{Key: proto.String("pid"), Value: proto.String(fmt.Sprintf("%d", row.Pid))},
			&aliyunsls.LogContent{Key: proto.String("direction"), Value: proto.String(
				func() string {
					if row.Dip == row.Sip { // 源IP和目的IP相等
						return "loop"
					}
					if localIp == row.Sip || row.Sip == data.LocalAddr {
						return "out"
					} else if localIp == row.Dip || row.Dip == data.LocalAddr {
						return "in"
					} else {
						return "unknown"
					}
				}(),
			)},
			&aliyunsls.LogContent{Key: proto.String("proto"), Value: proto.String(row.Proto)},
			&aliyunsls.LogContent{Key: proto.String("source_ip"), Value: proto.String(row.Sip)},
			&aliyunsls.LogContent{Key: proto.String("destination_ip"), Value: proto.String(row.Dip)},
			&aliyunsls.LogContent{Key: proto.String("source_port"), Value: proto.String(fmt.Sprintf("%d", row.Sport))},
			&aliyunsls.LogContent{Key: proto.String("destination_port"), Value: proto.String(fmt.Sprintf("%d", row.Dport))},
			&aliyunsls.LogContent{Key: proto.String("socket"), Value: proto.String(row.Socket)},
			&aliyunsls.LogContent{Key: proto.String("session_id"), Value: proto.String(fmt.Sprintf("%d", row.Sid))},
			&aliyunsls.LogContent{Key: proto.String("hostip"), Value: proto.String(localIp)},
			&aliyunsls.LogContent{Key: proto.String("hostname"), Value: proto.String(localName)},
			//&aliyunsls.LogContent{Key: proto.String("instance_id"), Value: proto.String(strings.Join(GetVMInstanceList(), ","))},
			&aliyunsls.LogContent{Key: proto.String("logtime"), Value: proto.String(row.LogTime)},
			&aliyunsls.LogContent{Key: proto.String("ppid"), Value: proto.String(fmt.Sprintf("%d", row.Ppid))},
			&aliyunsls.LogContent{Key: proto.String("uid"), Value: proto.String(fmt.Sprintf("%d", row.Uid))},
			&aliyunsls.LogContent{Key: proto.String("username"), Value: proto.String(row.UserName)},
			&aliyunsls.LogContent{Key: proto.String("cpuid"), Value: proto.String(fmt.Sprintf("%d", row.Cpuid))},
			&aliyunsls.LogContent{Key: proto.String("task"), Value: proto.String(row.Comm)},
			&aliyunsls.LogContent{Key: proto.String("file_path"), Value: proto.String(row.Path)},
			&aliyunsls.LogContent{Key: proto.String("file_name"), Value: proto.String(filepath.Base(row.Path))},
			&aliyunsls.LogContent{Key: proto.String("cmdline"), Value: proto.String(row.Argv)},
			&aliyunsls.LogContent{Key: proto.String("cwd"), Value: proto.String(row.Pwd)},
			&aliyunsls.LogContent{Key: proto.String("process_line"), Value: proto.String(string(row.Line))},
			&aliyunsls.LogContent{Key: proto.String("start_time"), Value: proto.String(string(row.StartTime))},
		)
		now := uint32(time.Now().Unix())
		logs = append(logs, &aliyunsls.Log{Time: &now, Contents: content})
	}

	loggroup := &aliyunsls.LogGroup{
		Topic:  proto.String("horus-process-monitor"),
		Source: proto.String(localIp),
		Logs:   logs,
	}

	return NetWorkSls.Client.PutLogs(NetWorkSls.ProjectName, NetWorkSls.LogStore, loggroup)
}

func InsertFileRows(rows map[string]data.FileRecord) error {
	logs := []*aliyunsls.Log{}
	localName, localIp, _ := GetLocalHostIpAndName()
	for _, row := range rows {
		content := []*aliyunsls.LogContent{}
		content = append(content,
			&aliyunsls.LogContent{Key: proto.String("pid"), Value: proto.String(fmt.Sprintf("%d", row.Pid))},
			&aliyunsls.LogContent{Key: proto.String("path"), Value: proto.String(row.Path)},
			//&aliyunsls.LogContent{Key: proto.String("instance_id"), Value: proto.String(strings.Join(GetVMInstanceList(), ","))},
			&aliyunsls.LogContent{Key: proto.String("hostip"), Value: proto.String(localIp)},
			&aliyunsls.LogContent{Key: proto.String("hostname"), Value: proto.String(localName)},
			&aliyunsls.LogContent{Key: proto.String("cmdline"), Value: proto.String(row.CmdLine)},
			&aliyunsls.LogContent{Key: proto.String("MD5"), Value: proto.String(row.MD5)},
			&aliyunsls.LogContent{Key: proto.String("file_size"), Value: proto.String(fmt.Sprintf("%d", row.FileSize))},
			&aliyunsls.LogContent{Key: proto.String("file_type"), Value: proto.String(row.FileType)},
			&aliyunsls.LogContent{Key: proto.String("log_time"), Value: proto.String(row.LogTime)},
			&aliyunsls.LogContent{Key: proto.String("access_time"), Value: proto.String(row.AccessTime.String())},
			&aliyunsls.LogContent{Key: proto.String("change_time"), Value: proto.String(row.ChangeTime.String())},
			&aliyunsls.LogContent{Key: proto.String("modify_time"), Value: proto.String(row.ModifyTime.String())},
		)
		now := uint32(time.Now().Unix())
		logs = append(logs, &aliyunsls.Log{Time: &now, Contents: content})
	}

	loggroup := &aliyunsls.LogGroup{
		Topic:  proto.String("horus-process-monitor"),
		Source: proto.String(localIp),
		Logs:   logs,
	}

	return FileSls.Client.PutLogs(FileSls.ProjectName, FileSls.LogStore, loggroup)
}
