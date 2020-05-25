// Code generated - DO NOT EDIT.

package eval

func Or(a *BoolEvaluator, b *BoolEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		if state.field != "" {
			if a.IsPartial {
				ea = func(ctx *Context) bool {
					return true
				}
			}
			if b.IsPartial {
				eb = func(ctx *Context) bool {
					return true
				}
			}
		}

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 || op2
				ctx.Logf("Evaluating %v || %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) || eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		if state.field != "" {
			if a.IsPartial {
				ea = true
			}
			if b.IsPartial {
				eb = true
			}
		}

		return &BoolEvaluator{
			Value:     ea || eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		if state.field != "" {
			if a.IsPartial {
				ea = func(ctx *Context) bool {
					return true
				}
			}
			if b.IsPartial {
				eb = true
			}
		}

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 || op2
				ctx.Logf("Evaluating %v || %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) || eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	if state.field != "" {
		if a.IsPartial {
			ea = true
		}
		if b.IsPartial {
			eb = func(ctx *Context) bool {
				return true
			}
		}
	}

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 || op2
			ctx.Logf("Evaluating %v || %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea || eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func And(a *BoolEvaluator, b *BoolEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		if state.field != "" {
			if a.IsPartial {
				ea = func(ctx *Context) bool {
					return true
				}
			}
			if b.IsPartial {
				eb = func(ctx *Context) bool {
					return true
				}
			}
		}

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 && op2
				ctx.Logf("Evaluating %v && %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) && eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		if state.field != "" {
			if a.IsPartial {
				ea = true
			}
			if b.IsPartial {
				eb = true
			}
		}

		return &BoolEvaluator{
			Value:     ea && eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		if state.field != "" {
			if a.IsPartial {
				ea = func(ctx *Context) bool {
					return true
				}
			}
			if b.IsPartial {
				eb = true
			}
		}

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 && op2
				ctx.Logf("Evaluating %v && %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) && eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	if state.field != "" {
		if a.IsPartial {
			ea = true
		}
		if b.IsPartial {
			eb = func(ctx *Context) bool {
				return true
			}
		}
	}

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 && op2
			ctx.Logf("Evaluating %v && %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea && eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func IntEquals(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 == op2
				ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) == eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea == eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 == op2
				ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) == eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 == op2
			ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea == eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func IntNotEquals(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 != op2
				ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) != eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea != eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 != op2
				ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) != eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 != op2
			ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea != eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func IntAnd(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *IntEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &IntEvaluator{
			DebugEval: func(ctx *Context) int {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 & op2
				ctx.Logf("Evaluating %v & %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) int {
				return ea(ctx) & eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &IntEvaluator{
			Value:     ea & eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &IntEvaluator{
			DebugEval: func(ctx *Context) int {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 & op2
				ctx.Logf("Evaluating %v & %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) int {
				return ea(ctx) & eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &IntEvaluator{
		DebugEval: func(ctx *Context) int {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 & op2
			ctx.Logf("Evaluating %v & %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) int {
			return ea & eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func IntOr(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *IntEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &IntEvaluator{
			DebugEval: func(ctx *Context) int {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 | op2
				ctx.Logf("Evaluating %v | %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) int {
				return ea(ctx) | eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &IntEvaluator{
			Value:     ea | eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &IntEvaluator{
			DebugEval: func(ctx *Context) int {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 | op2
				ctx.Logf("Evaluating %v | %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) int {
				return ea(ctx) | eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &IntEvaluator{
		DebugEval: func(ctx *Context) int {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 | op2
			ctx.Logf("Evaluating %v | %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) int {
			return ea | eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func IntXor(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *IntEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &IntEvaluator{
			DebugEval: func(ctx *Context) int {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 ^ op2
				ctx.Logf("Evaluating %v ^ %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) int {
				return ea(ctx) ^ eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &IntEvaluator{
			Value:     ea ^ eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &IntEvaluator{
			DebugEval: func(ctx *Context) int {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 ^ op2
				ctx.Logf("Evaluating %v ^ %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) int {
				return ea(ctx) ^ eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &IntEvaluator{
		DebugEval: func(ctx *Context) int {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 ^ op2
			ctx.Logf("Evaluating %v ^ %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) int {
			return ea ^ eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func StringEquals(a *StringEvaluator, b *StringEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 == op2
				ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) == eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea == eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 == op2
				ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) == eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 == op2
			ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea == eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func StringNotEquals(a *StringEvaluator, b *StringEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 != op2
				ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) != eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea != eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 != op2
				ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) != eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 != op2
			ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea != eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func BoolEquals(a *BoolEvaluator, b *BoolEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 == op2
				ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) == eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea == eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 == op2
				ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) == eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 == op2
			ctx.Logf("Evaluating %v == %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea == eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func BoolNotEquals(a *BoolEvaluator, b *BoolEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 != op2
				ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) != eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea != eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 != op2
				ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) != eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 != op2
			ctx.Logf("Evaluating %v != %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea != eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func GreaterThan(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 > op2
				ctx.Logf("Evaluating %v > %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) > eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea > eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 > op2
				ctx.Logf("Evaluating %v > %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) > eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 > op2
			ctx.Logf("Evaluating %v > %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea > eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func GreaterOrEqualThan(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 >= op2
				ctx.Logf("Evaluating %v >= %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) >= eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea >= eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 >= op2
				ctx.Logf("Evaluating %v >= %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) >= eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 >= op2
			ctx.Logf("Evaluating %v >= %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea >= eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func LesserThan(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 < op2
				ctx.Logf("Evaluating %v < %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) < eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea < eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 < op2
				ctx.Logf("Evaluating %v < %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) < eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 < op2
			ctx.Logf("Evaluating %v < %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea < eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}

func LesserOrEqualThan(a *IntEvaluator, b *IntEvaluator, opts *Opts, state *State) *BoolEvaluator {
	partialA, partialB := a.IsPartial, b.IsPartial

	if a.Eval == nil || (a.Field != "" && a.Field != state.field) {
		partialA = true
	}
	if b.Eval == nil || (b.Field != "" && b.Field != state.field) {
		partialB = true
	}
	isPartialLeaf := partialA && partialB

	if a.Field != "" && b.Field != "" {
		isPartialLeaf = true
	}

	if a.Eval != nil && b.Eval != nil {
		ea, eb := a.Eval, b.Eval
		dea, deb := a.DebugEval, b.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), deb(ctx)
				result := op1 <= op2
				ctx.Logf("Evaluating %v <= %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) <= eb(ctx)
			},
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval == nil && b.Eval == nil {
		ea, eb := a.Value, b.Value

		return &BoolEvaluator{
			Value:     ea <= eb,
			IsPartial: isPartialLeaf,
		}
	}

	if a.Eval != nil {
		ea, eb := a.Eval, b.Value
		dea := a.DebugEval

		return &BoolEvaluator{
			DebugEval: func(ctx *Context) bool {
				ctx.evalDepth++
				op1, op2 := dea(ctx), eb
				result := op1 <= op2
				ctx.Logf("Evaluating %v <= %v => %v", op1, op2, result)
				ctx.evalDepth--
				return result
			},
			Eval: func(ctx *Context) bool {
				return ea(ctx) <= eb
			},
			IsPartial: isPartialLeaf,
		}
	}

	ea, eb := a.Value, b.Eval
	deb := b.DebugEval

	return &BoolEvaluator{
		DebugEval: func(ctx *Context) bool {
			ctx.evalDepth++
			op1, op2 := ea, deb(ctx)
			result := op1 <= op2
			ctx.Logf("Evaluating %v <= %v => %v", op1, op2, result)
			ctx.evalDepth--
			return result
		},
		Eval: func(ctx *Context) bool {
			return ea <= eb(ctx)
		},
		IsPartial: isPartialLeaf,
	}
}
