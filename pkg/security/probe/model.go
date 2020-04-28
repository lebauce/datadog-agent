//go:generate go run github.com/DataDog/datadog-agent/pkg/security/generators/accessors -output model_accessors.go

package probe

type Model struct {
	event          *Event
	dentryResolver *DentryResolver
}

func (m *Model) SetData(data interface{}) {
	m.event = data.(*Event)
}
