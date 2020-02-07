// Copyright PT Dymar Jaya Indonesia
// Date February 2020
// RestAPI Thales payShield HSM using Golang
// Code by Mudito Adi Pranowo
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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/spf13/viper"
)

type PinVer struct {
	Tpk        string `json:"tpk"`
	Pvk        string `json:"pvk"`
	Pinblock   string `json:"pinblock"`
	Pan        string `json:"pan"`
	Dectable   string `json:"dectable"`
	Pinvaldata string `json:"pinvaldata"`
	Pinoffset  string `json:"pinoffset"`
}

/* Verify PIN
{"tpk": "TEFF270C330101C2D6B23DF72EA8FFEBD0E491D62E2E3D151","pvk": "9B395FB9FE5F07DA","pinblock": "EEC12744E8F13E16","pan": "923000000431","dectable": "3456789012345678","pinvaldata": "9230000N0431","pinoffset": "330309FFFFFF"}
*/

func DA(json PinVer) (errcode string) {

	HsmLmkVariant := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("DA")
	tpk := []byte(json.Tpk)
	pvk := []byte(json.Pvk)
	pinlen := []byte("12")
	pinblock := []byte(json.Pinblock)
	pinblockformat := []byte("01")
	checklen := []byte("06")
	pan := []byte(json.Pan)
	dectable := []byte(json.Dectable)
	pinvaldata := []byte(json.Pinvaldata)
	pinoffset := []byte(json.Pinoffset)

	commandMessage := Join(
		messageheader,
		commandcode,
		tpk,
		pvk,
		pinlen,
		pinblock,
		pinblockformat,
		checklen,
		pan,
		dectable,
		pinvaldata,
		pinoffset,
	)

	responseMessage := Connect(HsmLmkVariant, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		errcode = string(responseMessage)[8:]
	}
	if errcode != "00" {
		errcode = string(responseMessage)[8:]
	}
	return
}

type InpEnc struct {
	Key       string `json:"key"`
	Cleartext string `json:"cleartext"`
}

/* Encrypt
{"key": "S1012822AN00S000153767C37E3DD24D17D98C9EB003C8BDAAEAABD6D4E62C1288358E24E910A49D1A75B157B813DA6903BDC1A5B9EA57FA0D01F4A0E2F9544E5", "cleartext": "aGVsbG8gd29ybGQhISEAAA=="}
*/

func M0(json InpEnc) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(json.Cleartext)
	datapad := zeroPadding([]byte(data), 8)
	datalen := leftPad(string(datapad), "0", 4)

	messageheader := []byte("HEAD")
	commandcode := []byte("M0")
	modeflag := []byte("00")
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(json.Key)
	messagelen := []byte(datalen)
	message := datapad

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = base64.URLEncoding.EncodeToString([]byte(string(responseMessage)[14:]))
	}
	if errcode != "00" {
		res = ""
	}
	return

}

type InpDec struct {
	Key        string `json:"key"`
	Ciphertext string `json:"ciphertext"`
}

/* Decrypt
{"key":"S1012822AN00S000153767C37E3DD24D17D98C9EB003C8BDAAEAABD6D4E62C1288358E24E910A49D1A75B157B813DA6903BDC1A5B9EA57FA0D01F4A0E2F9544E5","ciphertext":"7ibaZ4PV0M937lTsupfhDQ=="}
*/

func M2(json InpDec) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(json.Ciphertext)
	datalen := leftPad(string(data), "0", 4)

	messageheader := []byte("HEAD")
	commandcode := []byte("M2")
	modeflag := []byte("00")
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(json.Key)
	messagelen := []byte(datalen)
	message := data

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = base64.URLEncoding.EncodeToString([]byte(string(responseMessage)[14:]))
	}
	if errcode != "00" {
		res = ""
	}
	return
}

type InpToken struct {
	Profile string `json:"profile"`
	Data    string `json:"data"`
}

/* Tokenize
{"profile":"creditcard","data": "9453677629008564"}
*/

func Token(json InpToken) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	profile := json.Profile

	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config profile error")
	}

	ppl := viper.GetInt(profile + "." + "preservedPrefixLength")
	psl := viper.GetInt(profile + "." + "preservedSuffixLength")
	lenData := len(json.Data)
	data := json.Data[ppl : (lenData-psl)]
	datappl := json.Data[:ppl]
	datapsl := json.Data[(lenData-psl):]

	messageheader := []byte("EFF1")
	commandcode := []byte("M0")
	modeflag := []byte("11")
	fperadixflag := []byte("U")
	fperadixvalue := []byte("00010")
	fpetweak, _ := hex.DecodeString(tweak(viper.GetString(profile + "." + "keyName")))
	fpetweaklen := []byte(fmt.Sprintf("%04X", len(string(fpetweak))))
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(viper.GetString(profile + "." + "key"))
	message, _ := hex.DecodeString(dectohex(data))
	messagelen := []byte(fmt.Sprintf("%04X", len(message)))

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		fperadixflag,
		fperadixvalue,
		fpetweaklen,
		fpetweak,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = datappl + hextodec(hex.EncodeToString([]byte(string(responseMessage)[14:]))) + datapsl
	}
	if errcode != "00" {
		res = ""
	}
	return

}

type InpDetoken struct {
	Profile string `json:"profile"`
	Token   string `json:"token"`
}

/* Detokenize
{"profile":"creditcard","token": "6288248669598239"}
*/

func Detoken(json InpDetoken) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	profile := json.Profile

	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config profile error")
	}

	ppl := viper.GetInt(profile + "." + "preservedPrefixLength")
	psl := viper.GetInt(profile + "." + "preservedSuffixLength")
	lenData := len(json.Token)
	data := json.Token[ppl : (lenData-psl)]
	datappl := json.Token[:ppl]
	datapsl := json.Token[(lenData-psl):]

	messageheader := []byte("EFF1")
	commandcode := []byte("M2")
	modeflag := []byte("11")
	fperadixflag := []byte("U")
	fperadixvalue := []byte("00010")
	fpetweak, _ := hex.DecodeString(tweak(viper.GetString(profile + "." + "keyName")))
	fpetweaklen := []byte(fmt.Sprintf("%04X", len(string(fpetweak))))
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(viper.GetString(profile + "." + "key"))
	message, _ := hex.DecodeString(dectohex(data))
	messagelen := []byte(fmt.Sprintf("%04X", len(message)))

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		fperadixflag,
		fperadixvalue,
		fpetweaklen,
		fpetweak,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = datappl + hextodec(hex.EncodeToString([]byte(string(responseMessage)[14:]))) + datapsl
	}
	if errcode != "00" {
		res = ""
	}
	return

}

/* Check Version
 */

func NC() (errcode string, lmk string, firmware string) {

	HsmLmkVariant := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("NC")

	commandMessage := Join(
		messageheader,
		commandcode,
	)

	responseMessage := Connect(HsmLmkVariant, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		lmk = string(responseMessage)[10 : 10+16]
		firmware = string(responseMessage)[26:]
	}
	if errcode != "00" {
		lmk = ""
		firmware = ""
	}

	return
}