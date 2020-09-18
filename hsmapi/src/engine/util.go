// Copyright PT Dymar Jaya Indonesia
// Date February 2020
// RestAPI Thales payShield HSM using Golang
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package engine

import (
	"bytes"
	"strconv"
	"strings"
	"encoding/hex"
	"fmt"
)

func leftPad(ss string, padStr string, pLen int) string {
	s := IntToHex(len(ss))
	pLenf := pLen - len(s)
	res :=  strings.Repeat(padStr, pLenf) + s
	return strings.ToUpper(res)

}

func zeroPadding(data []byte, blockSize int) []byte {
	if len(data) %8 ==0 {
		return data
	}

	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(data, padtext...)
}

func IntToHex(nn int) string{
	n := int64(nn)
	return string([]byte(strconv.FormatInt(n, 16)))
}

func reverse(str string) string {
	s,_ :=hex.DecodeString(str)
    res := make([]byte, len(s))
    prevPos, resPos := 0, len(s)
    for pos := range s {
        resPos -= pos - prevPos
        copy(res[resPos:], s[prevPos:pos])
        prevPos = pos
    }
    copy(res[0:], s[prevPos:])
    return string(hex.EncodeToString(res))
}

func tweak(str string) string {
	bytes := []byte(str)

 	var res int = 65537
 	for i := 0; i < len(str); i++ {
 		res = res*3+int(bytes[i])
 	}

 	x := fmt.Sprintf("%02x", res)

	return strings.ToUpper(reverse(fmt.Sprintf("%016s", x)))
}

func dectohex(s string) string{
	bytes := []byte(s)
	var str strings.Builder
	for i := 0; i < len(s); i++ {
		var hexa string = strings.ToUpper(fmt.Sprintf("%02c", int(bytes[i])))
		str.WriteString(hexa)
	}
	return str.String()
}

func hextodec(s string) string{
	bytes := []byte(s)
	var str strings.Builder
	for i := 0; i < len(s); i++ {
		a := fmt.Sprintf("%s",string(bytes[i+1]))
		str.WriteString(a)
		i++
		
	}
	return str.String()
}
