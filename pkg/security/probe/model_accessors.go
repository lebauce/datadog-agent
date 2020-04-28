// Code generated - DO NOT EDIT.

package probe

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/security/secl/eval"
	"github.com/pkg/errors"
)

func (m *Model) GetEvaluator(key string) (interface{}, []string, error) {
	switch key {

	case "process.name":

		return &eval.StringEvaluator{
			Eval:      func(ctx *eval.Context) string { return m.event.Process.GetComm() },
			DebugEval: func(ctx *eval.Context) string { return m.event.Process.GetComm() },
			Field:     key,
		}, []string{"process"}, nil

	case "mkdir.filename":

		return &eval.StringEvaluator{
			Eval:      func(ctx *eval.Context) string { return m.dentryResolver.Resolve(m.event.Mkdir.SrcPathnameKey) },
			DebugEval: func(ctx *eval.Context) string { return m.dentryResolver.Resolve(m.event.Mkdir.SrcPathnameKey) },
			Field:     key,
		}, []string{"fs"}, nil

	}

	return nil, nil, errors.Wrap(eval.ErrFieldNotFound, fmt.Sprintf("key '%s' not found", key))
}
