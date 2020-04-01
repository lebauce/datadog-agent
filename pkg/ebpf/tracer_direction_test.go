// +build linux_bpf

package ebpf

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/stretchr/testify/assert"
)

func TestIncomingTCPDirection(t *testing.T) {
	tr := &Tracer{
		portMapping: network.NewPortMapping(NewDefaultConfig().ProcRoot, true, true),
	}

	tr.portMapping.AddMapping(8000)
	connStat := CreateConnectionStat("10.2.25.1", "38.122.226.210", 8000, 80, network.TCP)
	connStat.Direction = tr.determineConnectionDirection(&connStat)
	assert.Equal(t, network.INCOMING, connStat.Direction)
}

func TestOutgoingTCPDirection(t *testing.T) {
	tr := &Tracer{
		portMapping: network.NewPortMapping(NewDefaultConfig().ProcRoot, true, true),
	}
	connStat := CreateConnectionStat("10.2.25.1", "38.122.226.210", 8000, 80, network.TCP)
	connStat.Direction = tr.determineConnectionDirection(&connStat)
	assert.Equal(t, network.OUTGOING, connStat.Direction)
}

func TestUDPConnectionDirection(t *testing.T) {
	tr := &Tracer{
		portMapping: network.NewPortMapping(NewDefaultConfig().ProcRoot, true, true),
	}
	connStat := CreateConnectionStat("10.2.25.1", "38.122.226.210", 5323, 8125, network.UDP)
	connStat.Direction = tr.determineConnectionDirection(&connStat)
	assert.Equal(t, network.NONE, connStat.Direction)
}

func CreateConnectionStat(source string, dest string, SPort uint16, DPort uint16, connType network.ConnectionType) network.ConnectionStats {
	return network.ConnectionStats{
		Source: util.AddressFromString(source),
		Dest:   util.AddressFromString(dest),
		SPort:  SPort,
		DPort:  DPort,
		Type:   connType,
	}
}
