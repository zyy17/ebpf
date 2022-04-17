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
	defaultUnionTypeHint    = "union_type_hint"
)

type btfMeta struct {
	spec              *btf.Spec
	outputDatatStruct *btf.Struct
}

var testdata = []byte{210, 4, 0, 0, 4, 0, 0, 0, 144, 232, 164, 53, 0, 0, 0, 0, 102, 111, 111, 46, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 102, 111, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 102, 111, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 86, 0, 0}

func main() {
	bm, err := NewBTFMeta("./testdata/event.bpf.o")
	if err != nil {
		log.Fatal(err)
	}

	o, err := bm.output(testdata)
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
		d, err := b.parseRawData(data[start:end], member.Name, member.Type)
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

var unionType int32

func (b *btfMeta) parseRawData(input []byte, name string, typ btf.Type) (interface{}, error) {
	if _, ok := typ.(*btf.Typedef); ok {
		underlayType, err := b.getUnderlayTypeFromTypedef(typ)
		if err != nil {
			return nil, err
		}
		return b.parseRawData(input, name, underlayType)
	}

	if _, ok := typ.(*btf.Struct); ok {
		return b.parseStructData(typ.(*btf.Struct), input)
	}

	if _, ok := typ.(*btf.Enum); ok {
		enumBtfType := typ.(*btf.Enum)
		var o int32
		binary.Read(bytes.NewReader(input[:4]), binary.LittleEndian, &o)
		unionType = o
		return enumBtfType.Values[o].Name, nil
	}

	if _, ok := typ.(*btf.Union); ok {
		unionBtfType := typ.(*btf.Union)
		return b.parseRawData(input, name, unionBtfType.Members[unionType].Type)
	}

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

func serialize(input interface{}, order binary.ByteOrder) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, order, input)
	return buf.Bytes()
}
