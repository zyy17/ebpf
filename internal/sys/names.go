package sys

import "github.com/cilium/ebpf/internal/unix"

// BPFObjName is a null-terminated string made up of
// 'A-Za-z0-9_' characters.
type ObjName [unix.BPF_OBJ_NAME_LEN]byte

// NewObjName truncates the result if it is too long.
func NewObjName(name string) ObjName {
	var result ObjName
	copy(result[:unix.BPF_OBJ_NAME_LEN-1], name)
	return result
}
