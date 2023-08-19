package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"os"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type io_stat -type io_key -target amd64 bpf vfs_io.bpf.c -- -I./headers
const (
	READ  = 0
	WRITE = 1

	fnKsysWrite = "ksys_write"
	fnKsysRead  = "ksys_read"
)

var writeKprobes = []string{
	fnKsysWrite,
}

var readKprobes = []string{
	fnKsysRead,
}

type StatData struct {
	ReadMap      map[uint32]uint64
	ReadByteMap  map[uint32]uint64
	WriteMap     map[uint32]uint64
	WriteByteMap map[uint32]uint64
}

func newStatData() *StatData {
	return &StatData{
		ReadMap:      make(map[uint32]uint64),
		ReadByteMap:  make(map[uint32]uint64),
		WriteMap:     make(map[uint32]uint64),
		WriteByteMap: make(map[uint32]uint64),
	}
}

type VfsIoStat struct {
	statData *StatData
	bpfObjs  *bpfObjects
	links    []link.Link
}

func (v *VfsIoStat) Close() {
	for _, l := range v.links {
		_ = l.Close()
	}
	_ = v.bpfObjs.Close()
}

func (v *VfsIoStat) Delta() (*StatData, error) {
	var key bpfIoKey
	var value bpfIoStat

	delta := newStatData()

	iter := v.bpfObjs.InesMap.Iterate()
	for {
		if found := iter.Next(&key, &value); !found {
			break
		}
		fd := key.Fd
		switch key.Type {
		case READ:
			delta.ReadMap[fd] = uint64(value.Time) - v.statData.ReadMap[fd]
			delta.ReadByteMap[fd] = value.Size - v.statData.ReadByteMap[fd]
			v.statData.ReadMap[fd] = uint64(value.Time)
			v.statData.ReadByteMap[fd] = value.Size
		case WRITE:
			delta.WriteMap[fd] = uint64(value.Time) - v.statData.WriteMap[fd]
			delta.WriteByteMap[fd] = value.Size - v.statData.WriteByteMap[fd]
			v.statData.WriteMap[fd] = uint64(value.Time)
			v.statData.WriteByteMap[fd] = value.Size
		default:
			return nil, fmt.Errorf("invalid type: %d", key.Type)
		}
	}

	return delta, nil
}

func NewVfsIo(pid uint32) (*VfsIoStat, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	var ve *ebpf.VerifierError
	spec, err := loadBpf()
	if err != nil {
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("loadBpf err: %+v", ve)
		}
		return nil, err
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"target": pid,
	}); err != nil {
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("RewriteConstants err: %+v", ve)
		}
		return nil, err
	}

	objs := bpfObjects{}
	opts := ebpf.CollectionOptions{}
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100

	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("LoadAndAssign err: %+%v", ve)
		}
		return nil, err
	}

	kps := []link.Link{}
	for _, kn := range writeKprobes {
		kp, err := link.Kprobe(kn, objs.VfsWriteProbe, nil)
		if err != nil {
			return nil, err
		}
		kps = append(kps, kp)
	}
	for _, kn := range readKprobes {
		kp, err := link.Kprobe(kn, objs.VfsReadProbe, nil)
		if err != nil {
			return nil, err
		}
		kps = append(kps, kp)
	}

	return &VfsIoStat{
		links:    kps,
		bpfObjs:  &objs,
		statData: newStatData(),
	}, nil
}

func main() {
	target := flag.Uint("pid", 0, "target process id")
	flag.Parse()

	vfsStat, err := NewVfsIo(uint32(*target))
	if err != nil {
		fmt.Printf("NewVfsIo: %+v\n", err)
	}

	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	fmt.Println("TYPE\tIOS\tTHROUGHPUT\tFD")
	for range t.C {
		delta, err := vfsStat.Delta()
		if err != nil {
			fmt.Printf("fetch data err: %+v\n", err)
			os.Exit(-1)
		}
		printData(mergeDeltas(delta, float64(3)))
	}
}

type mergeData struct {
	fd         uint32
	ttype      string
	ios        float64
	throughput float64
}

func mergeDeltas(delta *StatData, interval float64) []mergeData {
	var printDatas []mergeData
	for key := range delta.WriteMap {
		printDatas = append(printDatas, mergeData{
			fd:         key,
			ttype:      "WRITE",
			ios:        float64(delta.WriteMap[key]) / interval,
			throughput: float64(delta.WriteByteMap[key]) / interval,
		})
	}
	for key := range delta.ReadMap {
		printDatas = append(printDatas, mergeData{
			fd:         key,
			ttype:      "READ",
			ios:        float64(delta.ReadMap[key]) / interval,
			throughput: float64(delta.ReadByteMap[key]) / interval,
		})
	}
	return printDatas
}

func printData(data []mergeData) {
	for _, d := range data {
		fmt.Printf("%s\t%02f\t%02f\t%d\n", d.ttype, d.ios, d.throughput, d.fd)
	}
}
