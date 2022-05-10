package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"unicode"

	"github.com/cilium/ebpf/internal/btf"
)

const (
	defaultOutputStructName = "event"
	defaultUnionTypeName    = "type"
)

type btfMeta struct {
	spec              *btf.Spec
	outputDatatStruct *btf.Struct
}

var verbose = flag.Bool("v", false, "verbose")

func main() {
	var (
		bpfFilePath      = flag.String("b", "./bin/event.bpf.o", "path to bpf file")
		testDataFilePath = flag.String("t", "./bin/testdata.bin", "path to test data file")
	)
	flag.Parse()

	bm, err := NewBTFMeta(*bpfFilePath)
	if err != nil {
		log.Fatal(err)
	}

	testdata, err := ioutil.ReadFile(*testDataFilePath)
	if err != nil {
		log.Fatal(err)
	}

	o, err := bm.output(testdata)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(o))
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

		if *verbose {
			fmt.Printf("%s: %d-%d\n", member.Name, start, end)
		}

		// 'member.name' will be the key of the map.
		d, err := b.parseBTFMember(data[start:end], member.Name, member.Type)
		if err != nil {
			return nil, err
		}
		outputMap[member.Name] = d
	}

	return outputMap, nil
}

var unionTypeHint int32

func (b *btfMeta) parseBTFMember(input []byte, name string, typ btf.Type) (interface{}, error) {
	if _, ok := typ.(*btf.Typedef); ok {
		underlayType, err := b.getUnderlayTypeFromTypedef(typ)
		if err != nil {
			return nil, err
		}
		// Recursively parse the data.
		return b.parseBTFMember(input, name, underlayType)
	}

	// Emebeded struct.
	if _, ok := typ.(*btf.Struct); ok {
		return b.parseStructData(typ.(*btf.Struct), input)
	}

	if _, ok := typ.(*btf.Enum); ok {
		enumBtfType := typ.(*btf.Enum)

		var o int32
		if err := binary.Read(bytes.NewReader(input[:4]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}

		// Record the hint.
		if name == defaultUnionTypeName {
			unionTypeHint = o
		}

		return enumBtfType.Values[o].Name, nil
	}

	if _, ok := typ.(*btf.Union); ok {
		unionBtfType := typ.(*btf.Union)
		return b.parseBTFMember(input, name, unionBtfType.Members[unionTypeHint].Type)
	}

	if parsed, ok := typ.(*btf.Int); ok {
		return b.parseBTFInt(input, parsed.Encoding.IsSigned(), parsed.Bits)
	}

	// Process char[] type data.
	if parsed, ok := typ.(*btf.Array); ok {
		typ := parsed.Type
		if d, ok := typ.(*btf.Int); ok {
			if (d.TypeName() == "char" || d.TypeName() == "unsigned char") && d.Bits == 8 {
				data := input[:bytes.IndexByte(input, 0)]
				if isAllPrintedChar(data) {
					return string(data), nil
				}
			}

			var (
				intarry []interface{}

				length = int(d.Bits) / 8
			)
			for i := 0; i < len(input) && i+length <= len(input); i += length {
				if *verbose {
					fmt.Printf("parse int array: [%d:%d]\n", i, i+length)
				}
				intdata, err := b.parseBTFInt(input[i:i+length], d.Encoding.IsSigned(), d.Bits)
				if err != nil {
					return nil, err
				}
				intarry = append(intarry, intdata)
			}
			return intarry, nil
		}
	}

	return nil, fmt.Errorf("unsupported btf type '%s'", typ.String())
}

// TODO: Can make it short ?
func (b *btfMeta) parseBTFInt(data []byte, signed bool, bits byte) (interface{}, error) {
	// Process uint64.
	if !signed && bits == 64 {
		var o uint64
		if err := binary.Read(bytes.NewReader(data[:8]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	// Process uint32.
	if !signed && bits == 32 {
		var o uint32
		if err := binary.Read(bytes.NewReader(data[:4]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	// Process uint16.
	if !signed && bits == 16 {
		var o uint16
		if err := binary.Read(bytes.NewReader(data[:2]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	// Process uint8.
	if !signed && bits == 8 {
		var o uint8
		if err := binary.Read(bytes.NewReader(data[:1]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	// Process int64.
	if signed && bits == 64 {
		var o int64
		if err := binary.Read(bytes.NewReader(data[:8]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	// Process int32.
	if signed && bits == 32 {
		var o int32
		if err := binary.Read(bytes.NewReader(data[:4]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	// Process int32.
	if signed && bits == 16 {
		var o int16
		if err := binary.Read(bytes.NewReader(data[:2]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	// Process int8.
	if signed && bits == 8 {
		var o int8
		if err := binary.Read(bytes.NewReader(data[:1]), binary.LittleEndian, &o); err != nil {
			return nil, err
		}
		return o, nil
	}

	return nil, fmt.Errorf("unsupported btf int, signed: %v, bits: %v", signed, bits)
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

func isAllPrintedChar(input []byte) bool {
	for _, c := range input {
		if !unicode.IsPrint(rune(c)) {
			return false
		}
	}
	return true
}

func serialize(input interface{}, order binary.ByteOrder) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, order, input)
	return buf.Bytes()
}
