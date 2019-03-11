package main

import (
	"fmt"
	"unicode"
)

func _dump(i int, b []byte) {
	fmt.Printf("%06d:", i)
	var j int
	for j = 0; j < len(b); j++ {
		if j%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Printf("%02x", b[j])
	}
	for ; j < 16; j++ {
		if j%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Printf("  ")
	}
	fmt.Print("  ")
	for _, v := range b {
		if unicode.IsPrint(rune(v)) {
			fmt.Print(string(v))
		} else {
			fmt.Print(".")
		}
	}
	fmt.Println()
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
		_dump(i, b[i:m])
	}
}
