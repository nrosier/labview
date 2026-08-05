package payload

import (
	"reflect"
	"strings"
)

// Normalize makes a payload's required lists and maps serialise as [] and {} rather than
// as null.
//
// Appendix A distinguishes `warnings: str[]` from `via?: str[]`. The first is required and
// may be empty; the second may be absent, and its absence means something. Go's encoder
// writes null for a nil slice either way, which would collapse that distinction and force
// every consumer — the UI included — to treat null as an empty list. Normalize fills in
// the required ones so that only the optional ones can ever be missing, and a null array
// anywhere in the payload becomes a bug rather than a case to handle.
//
// It is a walk over the payload types rather than a rule the builders must remember,
// because "remember to allocate every slice" is a discipline that holds until it doesn't,
// and the failure is silent.
//
// Optional fields are left exactly as they are: a nil pointer stays nil, and a nil slice
// tagged omitempty stays absent. v must be a non-nil pointer.
func Normalize(v any) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return
	}
	normalize(rv.Elem())
}

func normalize(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			normalize(v.Elem())
		}

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			fv := v.Field(i)
			if required(f) {
				fill(fv)
			}
			normalize(fv)
		}

	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			normalize(v.Index(i))
		}

	case reflect.Map:
		// Map values are not addressable, so anything that needs filling has to be
		// normalised in a copy and written back. No payload map holds a composite value
		// today; this keeps that from being a silent assumption.
		if !composite(v.Type().Elem()) {
			return
		}
		for _, k := range v.MapKeys() {
			c := reflect.New(v.Type().Elem()).Elem()
			c.Set(v.MapIndex(k))
			normalize(c)
			v.SetMapIndex(k, c)
		}
	}
}

// required reports whether a field is one Appendix A always writes: no `json:"-"`, and no
// omitempty. A field with no json tag at all counts as required, since the encoder writes
// it unconditionally.
func required(f reflect.StructField) bool {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return true
	}
	name, opts, _ := strings.Cut(tag, ",")
	if name == "-" && opts == "" {
		return false
	}
	for opts != "" {
		var opt string
		opt, opts, _ = strings.Cut(opts, ",")
		if opt == "omitempty" {
			return false
		}
	}
	return true
}

// fill replaces a nil slice or map with an empty one. Anything else is left alone —
// notably a nil pointer, whose nilness is the fact.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.Slice, reflect.Map:
	default:
		return // a struct, a scalar, or a pointer whose nilness is the fact
	}
	if !v.CanSet() || !v.IsNil() {
		return
	}
	if v.Kind() == reflect.Slice {
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		return
	}
	v.Set(reflect.MakeMap(v.Type()))
}

// composite reports whether a type can itself contain a required list or map.
func composite(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct, reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
		return true
	}
	return false
}

// Ptr returns a pointer to v. It exists for the optional fields of Appendix A, where the
// difference between a reading of zero and no reading at all is the whole point:
// payload.Ptr(0) is "zero restarts", nil is "the Engine said nothing".
func Ptr[T any](v T) *T { return &v }
