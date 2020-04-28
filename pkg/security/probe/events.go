package probe

import (
	"bytes"
	"encoding/binary"
	"unsafe"
)

var byteOrder binary.ByteOrder

type OpenEvent struct {
	Filename string `yaml:"filename" field:"filename" tags:"fs"`
	Flags    int    `yaml:"flags" field:"flags" tags:"fs"`
	Mode     int    `yaml:"mode" field:"mode" tags:"fs"`
}

type MkdirEvent struct {
	Flags             int32  `json:"flags,omitempty" field:"flags"`
	Mode              int32  `json:"mode,omitempty" field:"mode"`
	SrcInode          uint32 `json:"src_inode,omitempty" field:"source_inode"`
	SrcPathnameKey    uint32 `json:"-" field:"src_pathname,string,dentryResolver"`
	SrcMountID        int32  `json:"src_mount_id,omitempty" field:"source_mount_id"`
	TargetInode       uint32 `json:"target_inode,omitempty" field:"target_inode"`
	TargetPathnameKey uint32 `json:"-" field:"-"`
	TargetMountID     int32  `json:"target_mount_id,omitempty" field:"target_mount_id"`
}

func (e *MkdirEvent) UnmarshalBinary(data []byte) (int, error) {
	e.Flags = int32(byteOrder.Uint32(data[0:4]))
	e.Mode = int32(byteOrder.Uint32(data[4:8]))
	e.SrcInode = byteOrder.Uint32(data[8:12])
	e.SrcPathnameKey = byteOrder.Uint32(data[12:16])
	e.SrcMountID = int32(byteOrder.Uint32(data[16:20]))
	e.TargetInode = byteOrder.Uint32(data[20:24])
	e.TargetPathnameKey = byteOrder.Uint32(data[24:28])
	e.TargetMountID = int32(byteOrder.Uint32(data[28:32]))
	return 32, nil
}

type UnlinkEvent struct {
	Filename string `yaml:"filename" field:"filename" tags:"fs"`
}

type RenameEvent struct {
	OldName string `yaml:"oldname" field:"oldname" tags:"fs"`
	NewName string `yaml:"newname" field:"newname" tags:"fs"`
}

type ContainerEvent struct {
	ID     string   `yaml:"id" field:"id" tags:"container"`
	Labels []string `yaml:"labels" field:"labels" tags:"container"`
}

type KernelEvent struct {
	Type      ProbeEventType `json:"retval" field:"type"`
	Timestamp uint64         `json:"-" field:"-"`
	Retval    int64          `json:"retval" field:"retval"`
}

func (k *KernelEvent) UnmarshalBinary(data []byte) (int, error) {
	k.Type = ProbeEventType(byteOrder.Uint64(data[0:8]))
	k.Timestamp = byteOrder.Uint64(data[8:16])
	k.Retval = int64(byteOrder.Uint64(data[16:24]))
	return 24, nil
}

type ProcessEvent struct {
	Pidns   uint64   `json:"pidns" field:"pidns" tags:"process"`
	Comm    [16]byte `json:"-" field:"name,string,GetComm()" tags:"process"`
	CommStr string   `json:"-" field:"-"`
	TTYName [64]byte `json:"-" field:"tty_name,string,GetTTY()" tags:"process"`
	Pid     uint32   `json:"pid" field:"pid" tags:"process"`
	Tid     uint32   `json:"tid" field:"tid" tags:"process"`
	UID     uint32   `json:"uid" field:"uid" tags:"process"`
	GID     uint32   `json:"gid" field:"gid" tags:"process"`
}

func (p *ProcessEvent) GetTTY() string {
	return string(p.TTYName[:])
}

func (p *ProcessEvent) GetComm() string {
	if len(p.CommStr) == 0 {
		p.CommStr = string(bytes.Trim(p.Comm[:], "\x00"))
	}
	return p.CommStr
}

func (p *ProcessEvent) UnmarshalBinary(data []byte) (int, error) {
	p.Pidns = byteOrder.Uint64(data[0:8])
	binary.Read(bytes.NewBuffer(data[8:24]), byteOrder, &p.Comm)
	binary.Read(bytes.NewBuffer(data[24:88]), byteOrder, &p.TTYName)
	p.Pid = byteOrder.Uint32(data[88:92])
	p.Tid = byteOrder.Uint32(data[92:96])
	p.UID = byteOrder.Uint32(data[96:100])
	p.GID = byteOrder.Uint32(data[100:104])
	return 104, nil
}

// genaccessors
type Event struct {
	Event     KernelEvent    `yaml:"event" field:"event"`
	Process   ProcessEvent   `yaml:"process" field:"process"`
	Open      OpenEvent      `yaml:"open" field:"open"`
	Mkdir     MkdirEvent     `yaml:"mkdir" field:"mkdir"`
	Unlink    UnlinkEvent    `yaml:"unlink" field:"unlink"`
	Rename    RenameEvent    `yaml:"rename" field:"rename"`
	Container ContainerEvent `yaml:"container" field:"container"`
}

func (e *Event) GetType() string {
	return e.Event.Type.String()
}

func (e *Event) UnmarshalBinary(data []byte) (int, error) {
	offset, err := e.Process.UnmarshalBinary(data)
	if err != nil {
		return offset, err
	}

	return offset, nil
}

func getHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

func init() {
	byteOrder = getHostByteOrder()
}
