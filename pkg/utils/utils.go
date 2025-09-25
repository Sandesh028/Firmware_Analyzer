package utils

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Flatten walks arbitrarily nested data structures (maps, slices, arrays)
// and returns a map keyed by dot-separated paths with stringified values.
// It is primarily used by the configuration parser to expose nested settings
// in a uniform representation for downstream modules.
func Flatten(prefix string, value any) map[string]string {
	out := make(map[string]string)
	flattenInto(out, prefix, value)
	return out
}

func flattenInto(out map[string]string, prefix string, value any) {
	switch v := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			next := k
			if prefix != "" {
				next = prefix + "." + k
			}
			flattenInto(out, next, v[k])
		}
	case []interface{}:
		for idx, item := range v {
			next := prefix + "[" + strconv.Itoa(idx) + "]"
			flattenInto(out, next, item)
		}
	case json.Number:
		out[prefix] = v.String()
	case string:
		out[prefix] = v
	case fmt.Stringer:
		out[prefix] = v.String()
	case nil:
		out[prefix] = ""
	default:
		out[prefix] = fmt.Sprint(v)
	}
}

// ContainsCredentialKeyword reports whether the provided key path appears to
// reference a credential. This is a heuristic used by both the configuration
// parser and secret scanner to prioritise findings.
func ContainsCredentialKeyword(key string) bool {
	lowered := strings.ToLower(key)
	keywords := []string{"pass", "secret", "token", "key", "auth", "cred"}
	for _, kw := range keywords {
		if strings.Contains(lowered, kw) {
			return true
		}
	}
	return false
}

// ShannonEntropy computes the Shannon entropy in bits of the supplied text.
// High entropy strings are likely to be randomly generated secrets such as
// API tokens. The function operates on runes to better support UTF-8 input.
func ShannonEntropy(text string) float64 {
	if text == "" {
		return 0
	}
	freq := make(map[rune]int)
	total := 0
	for _, r := range text {
		freq[r]++
		total++
	}
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// LooksLikeText checks whether a byte slice appears to be text by verifying
// it does not contain excessive NUL bytes and that it is valid UTF-8.
func LooksLikeText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	const maxNullRatio = 0.2
	nulls := 0
	for _, b := range data {
		if b == 0 {
			nulls++
		}
	}
	if float64(nulls)/float64(len(data)) > maxNullRatio {
		return false
	}
	return utf8.Valid(data)
}
