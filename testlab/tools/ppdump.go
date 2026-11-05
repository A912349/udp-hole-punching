package main

// ppdump: structural dump of a decompressed Go profiler protobuf stream.
// Handles length-prefixed fields and the legacy inline messages (wire kinds
// 3/5/7) that the Go runtime profiler emits. Usage: ppdump profile.pb

import (
	"fmt"
	"os"
)

// readVarint returns (value, nextPos); nextPos < 0 means failure.
func readVarint(b []byte, pos int) (uint64, int) {
	v := uint64(0)
	for i := pos; i < len(b) && i-pos < 10; i++ {
		c := b[i]
		v |= uint64(c&0x7f) << (7 * uint(i-pos))
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, -1
}

func isText(b []byte) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' {
			continue
		}
		return false
	}
	return true
}

type Node struct {
	field int
	kind  int
	v     uint64
	b     []byte
	kids  []Node
	sub   bool
}

// parseMsg parses fields into nodes. A lower field number than the last seen
// terminates the current message; that tag belongs to an outer message, so we
// return its position.
func parseMsg(b []byte, pos int, stop int, depth int) ([]Node, int, bool) {
	var nodes []Node
	last := 0
	for pos < stop {
		tag, p2 := readVarint(b, pos)
		if p2 < 0 {
			return nil, 0, false
		}
		field := int(tag >> 3)
		kind := int(tag & 7)
		if field == 0 {
			return nil, 0, false
		}
		if field < last {
			last = 0
		}
		last = field
		n := Node{field: field, kind: kind}
		switch kind {
		case 0:
			v, p3 := readVarint(b, p2)
			if p3 < 0 {
				return nil, 0, false
			}
			n.v = v
			nodes = append(nodes, n)
			pos = p3
		case 2:
			ln, p3 := readVarint(b, p2)
			if p3 < 0 || ln > uint64(stop-p3) {
				return nil, 0, false
			}
			slice := b[p3 : p3+int(ln)]
			n.b = slice
			inner, endi, ok := parseMsg(slice, 0, len(slice), depth+1)
			if ok && endi == len(slice) && len(inner) > 0 {
				n.kids = inner
				n.sub = true
			}
			nodes = append(nodes, n)
			pos = p3 + int(ln)
		case 3, 7:
			kids, endp, ok := parseMsg(b, p2, stop, depth+1)
			if !ok || endp < p2 {
				return nil, 0, false
			}
			n.kids = kids
			n.sub = true
			nodes = append(nodes, n)
			pos = endp
		case 5:
			// Repeated inline message list: elements back to back.
			p := p2
			for {
				kids, endp, ok := parseMsg(b, p, stop, depth+1)
				if !ok {
					break
				}
				n2 := Node{field: field, kind: 3, kids: kids, sub: true}
				nodes = append(nodes, n2)
				if endp <= p {
					break
				}
				p = endp
				if p >= stop {
					break
				}
				tag2, q2 := readVarint(b, p)
				if q2 < 0 || int(tag2>>3) > field {
					break
				}
			}
			pos = p
		default:
			return nil, 0, false
		}
	}
	return nodes, pos, true
}

const showFirst = 3

func dump(nodes []Node, indent string) {
	i := 0
	for i < len(nodes) {
		n := nodes[i]
		j := i + 1
		for j < len(nodes) && nodes[j].field == n.field && nodes[j].kind == n.kind {
			j++
		}
		reps := j - i
		for k := i; k < j && k-i < showFirst; k++ {
			m := nodes[k]
			if m.sub {
				fmt.Printf("%s#%d.%d {\n", indent, m.field, m.kind)
				dump(m.kids, indent+"  ")
				fmt.Printf("%s}%d same-tag siblings\n", indent, reps)
			} else if m.kind == 2 && isText(m.b) {
				fmt.Printf("%s#%d.%d str %q\n", indent, m.field, m.kind, stringOf(m.b))
			} else if m.kind == 2 {
				fmt.Printf("%s#%d.%d bytes[%d]\n", indent, m.field, m.kind, len(m.b))
			} else {
				fmt.Printf("%s#%d.%d val %d\n", indent, m.field, m.kind, m.v)
			}
		}
		i = j
	}
}

func hexDigit(x byte) byte {
	return "0123456789abcdef"[int(x&0xf)]
}

func stringOf(b []byte) string {
	out := make([]byte, 0, len(b)*4)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if (c >= 0x20 && c <= 0x7e) || c == '\t' {
			out = append(out, c)
		} else {
			out = append(out, byte('<'), hexDigit(c>>4), hexDigit(c), byte('>'))
		}
	}
	return string(out)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ppdump profile.pb")
		return
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("read failed: %v\n", err)
		return
	}
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		fmt.Println("still gzip: run gunzip -c first")
		return
	}
	nodes, end, ok := parseMsg(b, 0, len(b), 0)
	if !ok || end != len(b) {
		fmt.Printf("root parse incomplete: ok=%t end=%d/%d\n", ok, end, len(b))
	}
	dump(nodes, "")
}
