package data

type Bpf_infoEventFork struct {
	Pid     int32
	Cpid    int32
	ArgSize uint64
	Argv    [128]uint8
}

type Bpf_infoeventBaseinfo struct {
	Pid       uint64
	Ppid      uint64
	StartTime uint64
	Uid       uint64
	Cpuid     uint64
	ArgSize   uint64
	Sid       uint64
	Pwd       [6][20]uint8
	Comm      [16]uint8
	Path      [80]uint8
	Argv      [128]uint8
}

type Bpf_tcpEventBaseinfo struct {
	Pid       uint64
	Ppid      uint64
	StartTime uint64
	Uid       uint64
	Cpuid     uint64
	ArgSize   uint64
	Sid       uint64

	Saddr uint32
	Daddr uint32
	Dport uint16
	Sport uint16
	Argv  [128]uint8
	Pwd   [6][20]uint8
	Comm  [16]uint8
}
