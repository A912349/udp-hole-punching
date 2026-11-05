package main

// ppreport decodes the length-delimited records emitted by Go CPU profiles.
// It is intentionally self-contained: no gprof or external symbolizer needed.

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type Node struct {
	field  int
	kind   int
	value  uint64
	data   []byte
	kids   []Node
	text   string
	textOK bool
	msg    bool
}

func varint(b []byte, p int) (uint64, int) {
	var v uint64
	for i := 0; p+i < len(b) && i < 10; i++ {
		c := b[p+i]
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c < 0x80 {
			return v, p + i + 1
		}
	}
	return 0, -1
}

func textBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// parse parses ordinary protobuf wire records. A length-delimited value is
// treated as a message only when its contents parse completely; otherwise it
// is retained as bytes/string.
func parse(b []byte, begin, end int) ([]Node, int) {
	var out []Node
	p := begin
	for p < end {
		tag, q := varint(b, p)
		if q < 0 || tag == 0 {
			return out, -1
		}
		n := Node{field: int(tag >> 3), kind: int(tag & 7)}
		p = q
		switch n.kind {
		case 0:
			var v uint64
			v, p = varint(b, p)
			if p < 0 {
				return out, -1
			}
			n.value = v
		case 1:
			if p+8 > end {
				return out, -1
			}
			n.data = b[p : p+8]
			p += 8
		case 2:
			ln, q2 := varint(b, p)
			if q2 < 0 || ln > uint64(end-q2) {
				return out, -1
			}
			p = q2
			n.data = b[p : p+int(ln)]
			if k, e := parse(n.data, 0, len(n.data)); e == len(n.data) && len(k) != 0 {
				n.msg, n.kids = true, k
			} else if len(n.data) == 0 || textBytes(n.data) {
				n.text, n.textOK = string(n.data), true
			}
			p += int(ln)
		case 5:
			if p+4 > end {
				return out, -1
			}
			n.data = b[p : p+4]
			p += 4
		default:
			return out, -1
		}
		out = append(out, n)
	}
	return out, p
}

var stringsTable []string
var frames []Node
var samples [][]uint64

func walk(ns []Node) {
	for _, n := range ns {
		if n.textOK {
			stringsTable = append(stringsTable, n.text)
		}
		if n.msg {
			// Frame records in the Go profile are all-varint records. Sample
			// records contain repeated two-varint location records.
			allVar := len(n.kids) >= 4 && len(n.kids) <= 8
			pairs := make([]uint64, 0)
			for _, k := range n.kids {
				if k.msg && len(k.kids) == 2 && k.kids[0].kind == 0 && k.kids[1].kind == 0 {
					pairs = append(pairs, k.kids[0].value)
				} else if k.kind != 0 {
					allVar = false
				}
			}
			if allVar {
				frames = append(frames, n)
			} else if len(pairs) != 0 {
				samples = append(samples, pairs)
			}
			walk(n.kids)
		}
	}
}

func likelyName(s string) bool {
	return strings.Contains(s, ".") && !strings.Contains(s, "/") && !strings.HasPrefix(s, "(") && s != "samples" && s != "count"
}

func packed(b []byte) []uint64 {
	var out []uint64
	for p := 0; p < len(b); {
		v, q := varint(b, p)
		if q < 0 {
			return out
		}
		out = append(out, v)
		p = q
	}
	return out
}

func vals(ns []Node, field int) []uint64 {
	var out []uint64
	for _, n := range ns {
		if n.field != field {
			continue
		}
		if n.kind == 0 {
			out = append(out, n.value)
		}
		if n.kind == 2 && !n.msg {
			out = append(out, packed(n.data)...)
		}
	}
	return out
}

func directReport(root []Node) {
	period := uint64(10000000)
	for _, n := range root {
		if n.field == 12 && n.kind == 0 {
			period = n.value
		}
	}
	fn := make(map[uint64]string)
	for _, n := range root {
		if n.field != 5 || !n.msg {
			continue
		}
		ids, names := vals(n.kids, 1), vals(n.kids, 2)
		if len(ids) > 0 && len(names) > 0 && names[0] < uint64(len(stringsTable)) {
			fn[ids[0]] = stringsTable[names[0]]
		}
	}
	loc := make(map[uint64][]string)
	for _, n := range root {
		if n.field != 4 || !n.msg {
			continue
		}
		ids := vals(n.kids, 1)
		if len(ids) == 0 {
			continue
		}
		for _, line := range n.kids {
			if line.field != 4 || !line.msg {
				continue
			}
			for _, fid := range vals(line.kids, 1) {
				if fn[fid] != "" {
					loc[ids[0]] = append(loc[ids[0]], fn[fid])
				}
			}
		}
	}
	type stat struct{ excl, incl uint64 }
	stats := make(map[string]stat)
	for _, n := range root {
		if n.field != 2 || !n.msg {
			continue
		}
		ids, values := vals(n.kids, 1), vals(n.kids, 2)
		if len(ids) == 0 || len(values) == 0 {
			continue
		}
		seen := make(map[string]bool)
		for i, id := range ids {
			for _, name := range loc[id] {
				x := stats[name]
				if i == 0 {
					x.excl++
				}
				if !seen[name] {
					x.incl++
					seen[name] = true
				}
				stats[name] = x
			}
		}
	}
	names := make([]string, 0, len(stats))
	for n := range stats {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return stats[names[i]].excl > stats[names[j]].excl })
	fmt.Printf("== hotspots (%dns/sample) ==\n", period)
	for _, n := range names {
		x := stats[n]
		fmt.Printf("%-56s excl=%d incl=%d exclNs=%d inclNs=%d\n", n, x.excl, x.incl, x.excl*period, x.incl*period)
	}
}

func dump(ns []Node, indent string) {
	for _, n := range ns {
		if n.msg {
			fmt.Printf("%s#%d.%d {\n", indent, n.field, n.kind)
			dump(n.kids, indent+"  ")
			fmt.Printf("%s}\n", indent)
		} else if n.kind == 0 {
			fmt.Printf("%s#%d.%d val %d\n", indent, n.field, n.kind, n.value)
		} else if n.text != "" {
			fmt.Printf("%s#%d.%d str %q\n", indent, n.field, n.kind, n.text)
		} else {
			fmt.Printf("%s#%d.%d bytes[%d]\n", indent, n.field, n.kind, len(n.data))
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ppreport profile.pb [--dump]")
		return
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}
	root, end := parse(b, 0, len(b))
	if end != len(b) {
		fmt.Printf("parse incomplete: end=%d/%d\n", end, len(b))
	}
	if len(os.Args) > 2 && os.Args[2] == "--dump" {
		dump(root, "")
		return
	}
	walk(root)
	fmt.Printf("root=%d strings=%d frames=%d samples=%d\n", len(root), len(stringsTable), len(frames), len(samples))
	directReport(root)
	return
	for i, s := range stringsTable {
		if likelyName(s) {
			fmt.Printf("name[%d]=%s\n", i, s)
		}
	}
	// Locate the frame field that indexes the embedded string table.
	bestField, bestHits := -1, 0
	for field := 0; field < 8; field++ {
		hits := 0
		for _, f := range frames {
			for _, k := range f.kids {
				if k.field == field && k.kind == 0 && k.value < uint64(len(stringsTable)) && likelyName(stringsTable[k.value]) {
					hits++
				}
			}
		}
		if hits > bestHits {
			bestField, bestHits = field, hits
		}
	}
	fmt.Printf("name-field=%d hits=%d\n", bestField, bestHits)
	frameName := make(map[uint64]string)
	for _, f := range frames {
		var id uint64
		for _, k := range f.kids {
			if k.field == 1 && k.kind == 0 {
				id = k.value
			}
		}
		for _, k := range f.kids {
			if k.field == bestField && k.kind == 0 && k.value < uint64(len(stringsTable)) && likelyName(stringsTable[k.value]) {
				frameName[id] = stringsTable[k.value]
			}
		}
	}
	type stat struct{ excl, incl uint64 }
	stats := make(map[string]stat)
	for _, st := range samples {
		seen := make(map[string]bool)
		for i, id := range st {
			n := frameName[id]
			if n == "" {
				continue
			}
			x := stats[n]
			if i == 0 {
				x.excl++
			}
			if !seen[n] {
				x.incl++
				seen[n] = true
			}
			stats[n] = x
		}
	}
	names := make([]string, 0, len(stats))
	for n := range stats {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return stats[names[i]].excl > stats[names[j]].excl })
	fmt.Println("== hotspots (10ms/sample) ==")
	for _, n := range names {
		x := stats[n]
		fmt.Printf("%-48s excl=%d incl=%d exclNs=%d inclNs=%d\n", n, x.excl, x.incl, x.excl*10000000, x.incl*10000000)
	}
}
