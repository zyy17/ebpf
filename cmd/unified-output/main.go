package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/cilium/ebpf/internal/btf"
)

const (
	defaultOutputStructName = "event"
)

type btfMeta struct {
	spec              *btf.Spec
	outputDatatStruct *btf.Struct
}

func main() {
	bm, err := NewBTFMeta("./testdata/event.bpf.o")
	if err != nil {
		log.Fatal(err)
	}

	o, err := bm.output(generateTestData("hello", "world", 100, 200))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("output:", string(o))
}

func NewBTFMeta(bpfObjectFile string) (*btfMeta, error) {
	data, err := ioutil.ReadFile(bpfObjectFile)
	if err != nil {
		return nil, err
	}

	spec, err := btf.LoadSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	var outputDataStruct *btf.Struct
	if err := spec.TypeByName(defaultOutputStructName, &outputDataStruct); err != nil {
		return nil, err
	}

	return &btfMeta{
		spec:              spec,
		outputDatatStruct: outputDataStruct,
	}, nil
}

func (b *btfMeta) output(input []byte) ([]byte, error) {
	m, err := b.parseStructData(b.outputDatatStruct, input)
	if err != nil {
		return nil, err
	}

	o, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	return o, nil
}

func (b *btfMeta) parseStructData(input *btf.Struct, data []byte) (map[string]interface{}, error) {
	var (
		length    uint32
		outputMap = make(map[string]interface{})
	)

	for i, member := range input.Members {
		if i == len(input.Members)-1 {
			length = input.Size - member.OffsetBits/8
		} else {
			length = (input.Members[i+1].OffsetBits - member.OffsetBits) / 8
		}

		start := member.OffsetBits / 8
		end := start + length

		fmt.Printf("%s: %d-%d\n", member.Name, start, end)
		d, err := b.parseRawData(data[start:end], member)
		if err != nil {
			return nil, err
		}
		outputMap[member.Name] = d
	}

	return outputMap, nil
}

// getUnderlayTypeFromTypedef will return the underlay type of the given typedef btf type.
func (b *btfMeta) getUnderlayTypeFromTypedef(input btf.Type) (underlayType btf.Type, err error) {
	underlayType = input
	for {
		if typedefData, ok := underlayType.(*btf.Typedef); ok {
			underlayType, err = b.spec.TypeByID(typedefData.Type.ID())
			if err != nil {
				return nil, err
			}
		} else {
			return underlayType, nil
		}
	}
}

func (b *btfMeta) parseRawData(input []byte, member btf.Member) (interface{}, error) {
	typ := member.Type
	if _, ok := typ.(*btf.Typedef); ok {
		underlayType, err := b.getUnderlayTypeFromTypedef(typ)
		if err != nil {
			return nil, err
		}
		return b.processBasicType(input, underlayType)
	}

	if _, ok := typ.(*btf.Struct); ok {
		return b.parseStructData(typ.(*btf.Struct), input)
	}

	return b.processBasicType(input, typ)
}

func (b *btfMeta) processBasicType(input []byte, typ btf.Type) (interface{}, error) {
	fmt.Printf("%s, data: %x\n", typ.String(), input)
	if parsed, ok := typ.(*btf.Int); ok {
		// Process uint64
		if !parsed.Encoding.IsSigned() && parsed.Bits == 64 {
			var o uint64
			if err := binary.Read(bytes.NewReader(input[:8]), binary.LittleEndian, &o); err != nil {
				return nil, err
			}
			return o, nil
		}

		// Process uint32
		if !parsed.Encoding.IsSigned() && parsed.Bits == 32 {
			var o uint32
			if err := binary.Read(bytes.NewReader(input[:4]), binary.LittleEndian, &o); err != nil {
				return nil, err
			}
			return o, nil
		}

		// Process int64
		if parsed.Encoding.IsSigned() && parsed.Bits == 64 {
			var o int64
			if err := binary.Read(bytes.NewReader(input[:8]), binary.LittleEndian, &o); err != nil {
				return nil, err
			}
			return o, nil
		}

		// Process int32
		if parsed.Encoding.IsSigned() && parsed.Bits == 32 {
			var o int32
			if err := binary.Read(bytes.NewReader(input[:4]), binary.LittleEndian, &o); err != nil {
				return nil, err
			}
			return o, nil
		}
	}

	// Process char[] type data.
	if parsed, ok := typ.(*btf.Array); ok {
		typ := parsed.Type
		if d, ok := typ.(*btf.Int); ok {
			if (d.TypeName() == "char" || d.TypeName() == "unsigned char") && d.Bits == 8 {
				return string(input[:bytes.IndexByte(input, 0)]), nil
			}
		}
	}

	return nil, fmt.Errorf("unsupported btf type '%s'", typ.String())
}

func generateTestData(file, task string, deltaNs, pid uint64) []byte {
	type foo struct {
		a int32
		b uint32
	}
	type event struct {
		pid  uint32
		_pad [4]byte

		deltaNs  uint64
		filename [32]byte
		task     [16]byte
		f        foo
	}

	e := &event{
		filename: [32]byte{},
		task:     [16]byte{},
		deltaNs:  deltaNs,
		pid:      uint32(pid),
		f:        foo{a: 1, b: 2},
	}
	copy(e.filename[:], file)
	copy(e.task[:], task)
	return serialize(e, binary.LittleEndian)
}

func serialize(input interface{}, order binary.ByteOrder) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, order, input)
	return buf.Bytes()
}
