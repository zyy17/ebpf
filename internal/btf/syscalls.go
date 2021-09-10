package btf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
)

func bpfGetBTFInfoByFD(fd *sys.FD, btf, name []byte) (*sys.BtfInfo, error) {
	info := sys.BtfInfo{
		Btf:     sys.NewSlicePointer(btf),
		BtfSize: uint32(len(btf)),
		Name:    sys.NewSlicePointer(name),
		NameLen: uint32(len(name)),
	}
	attr := sys.ObjGetInfoByFdAttr{
		BpfFd:   fd.Uint(),
		InfoLen: uint32(unsafe.Sizeof(info)),
		Info:    sys.NewPointer(unsafe.Pointer(&info)),
	}
	if _, err := sys.BPF(&attr); err != nil {
		return nil, fmt.Errorf("can't get program info: %w", err)
	}

	return &info, nil
}
