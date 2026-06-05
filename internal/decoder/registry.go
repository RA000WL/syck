package decoder

import "sync"

type Decoder func(string) []DecodeResult

type Registry struct {
	mu    sync.RWMutex
	decs  map[string]Decoder
	order []string
}

func NewRegistry() *Registry {
	return &Registry{decs: map[string]Decoder{}}
}

func (r *Registry) Register(name string, d Decoder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.decs[name]; !ok {
		r.order = append(r.order, name)
	}
	r.decs[name] = d
}

func (r *Registry) Active(flags Flags) []Decoder {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Decoder, 0, len(r.order))
	for _, name := range r.order {
		switch name {
		case "base64":
			if flags.Base64 {
				out = append(out, r.decs[name])
			}
		case "base64url":
			if flags.Base64URL {
				out = append(out, r.decs[name])
			}
		case "hex":
			if flags.Hex {
				out = append(out, r.decs[name])
			}
		case "unicode":
			if flags.Unicode {
				out = append(out, r.decs[name])
			}
		case "url":
			if flags.URL {
				out = append(out, r.decs[name])
			}
		case "jwt":
			if flags.JWT {
				out = append(out, r.decs[name])
			}
		case "doublebase64":
			if flags.DoubleBase64 {
				out = append(out, r.decs[name])
			}
		default:
			out = append(out, r.decs[name])
		}
	}
	return out
}
