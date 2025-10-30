// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"snoop/common/data"
	"snoop/sls"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux bpf_info bpf/src/proc_info.c -- -I./bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux bpf_tcp bpf/src/tcpstate.c -- -I./bpf/include

var FileMap = map[string]bool{"python": true, "bash": true, "sh": true}

var mapSizeRatio = 8

var spec *btf.Spec

//go:embed btf/vmlinux-4.9.168-016.ali3000.alios7.x86_64
var btfs embed.FS

func initialize() error {
	// Load the BTF from the embedded file
	file, err := btfs.ReadFile("btf/vmlinux-4.9.168-016.ali3000.alios7.x86_64")
	if err != nil {
		return fmt.Errorf("reading BTF data: %w", err)
	}

	s, err := btf.LoadSpecFromReader(bytes.NewReader(file))
	if err != nil {
		return fmt.Errorf("could not load BTF spec: %v", err)
	}

	spec = s
	return nil
}

func main() {
	// Initialize BTF
	if err := initialize(); err != nil {
		log.Fatalf("Initialization BTF error: %v", err)
	}

	// Name of the kernel function to trace.
	fn := "sys_execve"
	fnTcp := "tcp_v4_connect"
	fnFork := "_do_fork"
	fnExit := "do_exit"

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs_info := bpf_infoObjects{}
	if err := loadBpf_infoObjects(&objs_info, &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: spec}}); err != nil {
		log.Fatalf("loading objectsinfo: %v", err)
	}
	defer objs_info.Close()

	objs_tcp := bpf_tcpObjects{}
	if err := loadBpf_tcpObjects(&objs_tcp, &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: spec}}); err != nil {
		log.Fatalf("loading objectstcp: %v", err)
	}
	defer objs_tcp.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by info. The read loop below polls this
	// map value once per second.

	kpinfo, err := link.Kprobe(fn, objs_info.KprobeExecvePath, nil)
	if err != nil {
		log.Fatalf("opening kprobeinfo: %s", err)
	}
	defer kpinfo.Close()

	kpexit, err := link.Kprobe(fnExit, objs_info.KprobeExit, nil)
	if err != nil {
		log.Fatalf("opening kprobexit: %s", err)
	}
	defer kpexit.Close()

	kpretinfo, err := link.Kretprobe(fn, objs_info.KretprobeExecveInfo, nil)
	if err != nil {
		log.Fatalf("opening kretprobeinfo: %s", err)
	}
	defer kpretinfo.Close()

	kpfork, err := link.Kretprobe(fnFork, objs_info.KretprobeForkInfo, nil)
	if err != nil {
		log.Fatalf("opening kprobefork: %s", err)
	}
	defer kpfork.Close()

	kptcp_entry, err := link.Kprobe(fnTcp, objs_tcp.TraceConnectEntry, nil)
	if err != nil {
		log.Fatalf("opening kprobetcp_entry: %s", err)
	}
	defer kptcp_entry.Close()

	kptcp_ret, err := link.Kretprobe(fnTcp, objs_tcp.TraceConnectV4Return, nil)
	if err != nil {
		log.Fatalf("opening kprobetcp_ret: %s", err)
	}
	defer kptcp_ret.Close()

	/// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rdinfo, err := perf.NewReader(objs_info.EventsInfo, os.Getpagesize()*mapSizeRatio)
	if err != nil {
		log.Fatalf("creating perf event readerinfo: %s", err)
	}
	defer rdinfo.Close()

	rdexit, err := perf.NewReader(objs_info.EventsExit, os.Getpagesize()*mapSizeRatio)
	if err != nil {
		log.Fatalf("creating perf event readerexit: %s", err)
	}
	defer rdexit.Close()

	rdfork, err := perf.NewReader(objs_info.EventsFork, os.Getpagesize()*mapSizeRatio)
	if err != nil {
		log.Fatalf("creating perf event readerfork: %s", err)
	}
	defer rdfork.Close()

	rdtcp, err := perf.NewReader(objs_tcp.Ipv4Events, os.Getpagesize()*mapSizeRatio)
	if err != nil {
		log.Fatalf("creating perf event readertcp: %s", err)
	}
	defer rdtcp.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rdinfo.Close(); err != nil {
			log.Fatalf("closing perf event readerinfo: %s", err)
		}
		if err := rdtcp.Close(); err != nil {
			log.Fatalf("closing perf event readertcp: %s", err)
		}
		if err := rdfork.Close(); err != nil {
			log.Fatalf("closing perf event reader fork: %s", err)
		}
		if err := rdexit.Close(); err != nil {
			log.Fatalf("closing perf event reader exit: %s", err)
		}
		os.Exit(0)
	}()

	data.InitLineMap()

	go extractBPFfork(rdfork)

	go extractBPFinfo(rdinfo)

	go extractBPFtcp(rdtcp)

	go extractBPFexit(rdexit)

	var ticker = time.NewTicker(30 * time.Second)
	for range ticker.C {
		fmt.Println("------------------------------------Separation line-----------------------------------------------")
		// data.MyProcMap.GetSlsData()
		// data.MyFileMap.GetSlsData()
		// data.MyNetMap.GetSlsData()
		ProcM := data.MyProcMap.GetSlsData()
		//formatProcRecord(ProcM)
		err := sls.InsertProcRows(ProcM)
		if err != nil {
			fmt.Println("push process to sls error:", err)
		}

		err = sls.InsertFileRows(data.MyFileMap.GetSlsData())
		if err != nil {
			fmt.Println("push file to sls error:", err)
		}

		NetM := data.MyNetMap.GetSlsData()
		formatNetRecord(NetM)
		err = sls.InsertNetWorkRows(NetM)
		if err != nil {
			fmt.Println("push network to sls error:", err)
		}
	}
}

func formatNetRecord(recs map[string]data.NetRecord) {

	for k, record := range recs {
		//处理当前工作目录
		if record.Pwd != "" {
			pwds := strings.Split(strings.TrimSpace(record.Pwd), " ")
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
			record.Pwd = pwd
		}
		//相对路径转绝对路径
		if len(record.Path) > 0 && record.Path[0] != '/' {
			record.Path = record.Pwd + "/" + record.Path
		}
		if len(record.Path) > 0 {
			record.Path, _ = filepath.Abs(record.Path) // 如果path为空的话，会变成当前目录
		}

		//根据uid获取用户名
		usr, _ := user.LookupId(fmt.Sprintf("%d", record.Uid))
		record.UserName = usr.Username

		recs[k] = record
	}
}

func ByteSliceToStrings(s []byte) []string {
	var res = []string{}
	var pre int
	for i := range s {
		if s[i] == 0 {
			res = append(res, string(s[pre:i]))
			pre = i + 1
		}
	}
	return res
}
