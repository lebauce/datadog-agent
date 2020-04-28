package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/DataDog/datadog-agent/pkg/ebpf/gobpf"
	eprobe "github.com/DataDog/datadog-agent/pkg/ebpf/probe"
	"github.com/DataDog/datadog-agent/pkg/ebpf/probe/types"
	"github.com/DataDog/datadog-agent/pkg/security/secl/eval"
	"github.com/iovisor/gobpf/bcc"
)

type EventHandler interface {
	HandleEvent(event *Event)
}

type Probe struct {
	*eprobe.Probe
	model   *Model
	handler EventHandler
}

func NewProbe() (*Probe, error) {
	bytecode, err := Asset("probe.o") // ioutil.ReadFile("pkg/security/ebpf/probe.o")
	if err != nil {
		return nil, err
	}

	module, err := gobpf.NewModuleFromReader(bytes.NewReader(bytecode))
	if err != nil {
		return nil, err
	}
	log.Printf("Loaded security agent eBPF module: %+v", module)

	p := &Probe{}

	ebpfProbe := &eprobe.Probe{
		Module: module,
		Tables: []*types.Table{
			{
				Name: "pathnames",
			},
			{
				Name: "process_discriminators",
			},
			{
				Name: "dentry_cache",
			},
		},
		Kprobes: []*types.KProbe{
			/*
				&eprobe.KProbe{
					Name:       "may_open",
					EntryFunc:  "trace_may_open",
					EntryEvent: "may_open.isra.0",
					ExitFunc:   "trace_ret_may_open",
					ExitEvent:  "may_open.isra.0",
				},
			*/
			&eprobe.KProbe{
				Name:       "vfs_mkdir",
				EntryFunc:  "kprobe/security_inode_mkdir",
				EntryEvent: "vfs_mkdir",
				ExitFunc:   "kretprobe/security_inode_mkdir",
				ExitEvent:  "vfs_mkdir",
			},
			/*
				&eprobe.KProbe{
					Name:       "vfs_link",
					EntryFunc:  "trace_vfs_link",
					EntryEvent: "vfs_link",
					ExitFunc:   "trace_ret_vfs_link",
					ExitEvent:  "vfs_link",
				},
				&eprobe.KProbe{
					Name:       "vfs_rename",
					EntryFunc:  "trace_vfs_rename",
					EntryEvent: "vfs_rename",
					ExitFunc:   "trace_ret_vfs_rename",
					ExitEvent:  "vfs_rename",
				},
				&eprobe.KProbe{
					Name:       "unlink_tracker",
					EntryFunc:  "trace_vfs_unlink",
					EntryEvent: "vfs_unlink",
					ExitFunc:   "trace_ret_vfs_unlink",
					ExitEvent:  "vfs_unlink",
				},
				&eprobe.KProbe{
					Name:       "rmdir_tracker",
					EntryFunc:  "trace_vfs_rmdir",
					EntryEvent: "vfs_rmdir",
					ExitFunc:   "trace_ret_vfs_rmdir",
					ExitEvent:  "vfs_rmdir",
				},
				&eprobe.KProbe{
					Name:       "setattr_tracker",
					EntryFunc:  "trace_security_inode_setattr",
					EntryEvent: "security_inode_setattr",
					ExitFunc:   "trace_ret_security_inode_setattr",
					ExitEvent:  "security_inode_setattr",
				},
			*/
		},
		PerfMaps: []*types.PerfMap{
			&types.PerfMap{
				Name:    "dentry_events",
				Handler: p.handleDentryEvent,
			},
			/*
				&types.PerfMap{
					Name:    "setattr_events",
					Handler: p.handleSecurityInodeSetattr,
				},
			*/
		},
	}

	if err := ebpfProbe.Load(); err != nil {
		return nil, err
	}

	p.Probe = ebpfProbe

	dentryResolver, err := NewDentryResolver(ebpfProbe)
	if err != nil {
		return nil, err
	}

	p.model = &Model{dentryResolver: dentryResolver}

	return p, nil
}

func (p *Probe) GetModel() eval.Model {
	return p.model
}

func (p *Probe) SetEventHandler(handler EventHandler) {
	p.handler = handler
}

func (p *Probe) DispatchEvent(event *Event) {
	if p.handler != nil {
		p.handler.HandleEvent(event)
	}
}

func (p *Probe) PushProcessDiscriminator(name string) {
	buffer := new(bytes.Buffer)
	table := p.Table("process_discriminators")
	if table == nil {
		panic(errors.New("failed to find process_discriminators"))
	}
	if err := binary.Write(buffer, bcc.GetHostByteOrder(), []byte(name)); err != nil {
		panic(err)
	}
	rep := make([]byte, 16)
	copy(rep, buffer.Bytes())
	table.Set(rep, []byte{1})

	// p.dumpDiscriminators()
}

/*
func (p *Probe) dumpDiscriminators() {
	var discriminator struct {
		Key   [16]byte
		Value uint8
	}

	discriminators := p.Tables["process_discriminators"]
	iterator := discriminators.Iter()
	for iterator.Next() {
		binary.Read(bytes.NewBuffer(iterator.Key()), bcc.GetHostByteOrder(), &discriminator.Key)
		binary.Read(bytes.NewBuffer(iterator.Leaf()), bcc.GetHostByteOrder(), &discriminator.Value)
		log.Printf("Discriminator: %v => %v\n", discriminator.Key, discriminator.Value)
	}
}
*/
