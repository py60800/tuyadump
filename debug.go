package main

import (
	"fmt"
	"unicode"
)

func _dump(i int, b []byte) string {
	r := fmt.Sprintf("%06d:", i)
	var j int
	for j = 0; j < len(b); j++ {
		if j%2 == 0 {
			r = r + " "
		}
		r = r + fmt.Sprintf("%02x", b[j])
	}
	for ; j < 16; j++ {
		if j%2 == 0 {
			r = r + " "
		}
		r = r + "  "
	}
	r = r + "   "
	for _, v := range b {
		if unicode.IsPrint(rune(v)) {
			r = r + string(v)
		} else {
			r = r + "."
		}
	}
	return r
}
func Dump(what string, b []byte) {
	fmt.Println("-->", what)
	for i := 0; ; i = i + 16 {
		if i >= len(b) {
			break
		}
		m := i + 16
		if m > len(b) {
			m = len(b)
		}
		fmt.Println(_dump(i, b[i:m]))
	}
}
func SDump(b []byte) string {
	r := ""
	for i := 0; ; i = i + 16 {
		if i >= len(b) {
			break
		}
		m := i + 16
		if m > len(b) {
			m = len(b)
		}
		r = r + _dump(i, b[i:m]) + "\n"
	}
	return r
}
func DDump(what string, b []byte) {
	if *debugMode {
		Dump(what, b)
	}
}
