package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"snoop/common/data"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

func extractBPFfork(rd *perf.Reader) {
	var event data.Bpf_infoEventFork
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from proc_fork perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event proc_fork ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing proc_fork perf event: %s", err)
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", event.Cpid))

		if !data.LineMap.IsExist(event.Cpid) {
			if len(cmdline) > int(event.ArgSize) {
				data.LineMap.WriteProcessLineMap(event.Cpid, event.Pid, unix.ByteSliceToString(cmdline))
			} else {
				data.LineMap.WriteProcessLineMap(event.Cpid, event.Pid, unix.ByteSliceToString(event.Argv[:event.ArgSize]))
			}

		}
	}
}

func extractBPFexit(rd *perf.Reader) {
	var pid int32
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from proc_fork perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event proc_fork ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &pid); err != nil {
			log.Printf("parsing proc_exit perf event: %s", err)
			continue
		}
		data.LineMap.DeleteProcessLineMap(pid)

	}
}

func extractBPFinfo(rd *perf.Reader) {
	var event data.Bpf_infoeventBaseinfo
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from proc_info perf event reader: %s", err)
			continue
		}
		if record.LostSamples != 0 {
			log.Printf("perf event proc_info ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing proc_info perf event: %s", err)
			continue
		}
		go handleBPFinfo(&event) //单独开一个协程处理字段，不阻塞读取内核态数据
	}
}

func handleBPFinfo(event *data.Bpf_infoeventBaseinfo) {
	rec := data.ProcRecord{
		Pid: int32(event.Pid),
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", rec.Pid))

	//需要从用户态获取的数据，优先读取，以防进程结束丢失
	rec.Path = unix.ByteSliceToString(event.Path[:])
	if rec.Path == "" { //从内核态读取到的路径为空，则从用户态获取
		rec.Path, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", rec.Pid))
	}
	//直接解析内核态数据
	rec.Uid = uint32(event.Uid)
	rec.Cpuid = uint32(event.Cpuid)
	rec.Ppid = int32(event.Ppid)
	rec.Comm = unix.ByteSliceToString(event.Comm[:])
	if len(cmdline) > int(event.ArgSize) {
		rec.Args = ByteSliceToStrings(cmdline)
		rec.Argv = strings.Join(rec.Args, " ")
	} else {
		rec.Args = ByteSliceToStrings(event.Argv[:event.ArgSize])
		rec.Argv = strings.Join(rec.Args, " ")
	}
	rec.Sid = uint32(event.Sid)
	rec.StartTime = time.Unix((data.SysBootTime+int64(event.StartTime))/data.Nanosecond, 0).Format("2006-01-02 15:04:05")
	for i := range event.Pwd {
		rec.Pwd += unix.ByteSliceToString(event.Pwd[i][:]) + " "
	}

	data.LineMap.WriteProcessLineMap(int32(event.Pid), int32(event.Ppid), rec.Argv)
	data.MyProcMap.Write(rec)
}

func extractBPFtcp(rd *perf.Reader) {
	var event data.Bpf_tcpEventBaseinfo
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading tcp_info from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event tcp_info ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing tcp_info perf event: %s", err)
			continue
		}
		go handleBPFtcp(&event) //单独开一个协程处理字段，不阻塞读取内核态数据
	}
}

func handleBPFtcp(event *data.Bpf_tcpEventBaseinfo) {
	var rec = data.NetRecord{
		ProcRecord: data.ProcRecord{Pid: int32(event.Pid)},
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", rec.Pid))

	// 网络连接相关进程的二进制文件的路径，内核态拿不到，从用户态获取。
	rec.Path, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", rec.Pid))
	rec.Ppid = int32(event.Ppid)
	rec.Sid = uint32(event.Sid)
	rec.Uid = uint32(event.Uid)
	rec.Comm = unix.ByteSliceToString(event.Comm[:])
	rec.Cpuid = uint32(event.Cpuid)
	if len(cmdline) > int(event.ArgSize) {
		rec.Args = ByteSliceToStrings(cmdline)
		rec.Argv = strings.Join(rec.Args, " ")
	} else {
		rec.Args = ByteSliceToStrings(event.Argv[:event.ArgSize])
		rec.Argv = strings.Join(rec.Args, " ")
	}
	rec.LogTime = time.Now().Format("2006-01-02 15:04:05")
	rec.StartTime = time.Unix((data.SysBootTime+int64(event.StartTime))/data.Nanosecond, 0).Format("2006-01-02 15:04:05")
	for i := range event.Pwd {
		rec.Pwd += unix.ByteSliceToString(event.Pwd[i][:]) + " "
	}

	rec.Sip = intToIP(event.Saddr)
	rec.Dip = intToIP(event.Daddr)

	rec.Socket = rec.Sip + ":" + strconv.Itoa(int(event.Sport)) + "-->" + rec.Dip + ":" + strconv.Itoa(int(event.Dport))

	rec.Sport = event.Sport
	rec.Dport = event.Dport
	rec.Proto = "tcp"

	data.LineMap.WriteProcessLineMap(int32(event.Pid), int32(event.Ppid), rec.Argv)
	data.MyNetMap.Write(&rec)
}

// intToIP 将 uint32 转换为 IPv4 地址字符串
func intToIP(n uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip.String()
}
