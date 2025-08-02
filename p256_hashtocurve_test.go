package nistec_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"filippo.io/nistec"
)

func TestMapToCurve(t *testing.T) {
	for _, tt := range []struct {
		u, x, y string
	}{
		{
			u: "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009",
			x: "ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5",
			y: "dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1",
		},
		{
			u: "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a",
			x: "51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
			y: "b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac",
		},
		{
			u: "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1",
			x: "5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48",
			y: "7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d93ecf",
		},
		{
			u: "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0",
			x: "019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f",
			y: "589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4252715446e",
		},
		{
			u: "0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c",
			x: "a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2",
			y: "4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e",
		},
		{
			u: "b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb",
			x: "7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66",
			y: "b765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9",
		},
		{
			u: "3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f6f8d805919",
			x: "c76aaa823aeadeb3f356909cb08f97eee46ecb157c1f56699b5efebddf0e6398",
			y: "776a6f45f528a0e8d289a4be12c4fab80762386ec644abf2bffb9b627e4352b1",
		},
		{
			u: "76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e3be1bf1d33",
			x: "418ac3d85a5ccc4ea8dec14f750a3a9ec8b85176c95a7022f391826794eb5a75",
			y: "fd6604f69e9d9d2b74b072d14ea13050db72c932815523305cb9e807cc900aff",
		},
		{
			u: "4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee51adb29fec",
			x: "d88b989ee9d1295df413d4456c5c850b8b2fb0f5402cc5c4c7e815412e926db8",
			y: "bb4a1edeff506cf16def96afff41b16fc74f6dbd55c2210e5b8f011ba32f4f40",
		},
		{
			u: "4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d20b4e269ee",
			x: "a281e34e628f3a4d2a53fa87ff973537d68ad4fbc28d3be5e8d9f6a2571c5a4b",
			y: "f6ed88a7aab56a488100e6f1174fa9810b47db13e86be999644922961206e184",
		},
	} {
		ubytes, err := hex.DecodeString(tt.u)
		if err != nil {
			panic(err)
		}
		p, err := nistec.P256MapToCurve(ubytes)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		bytes := p.Bytes()
		x, y := bytes[1:33], bytes[33:]
		if fmt.Sprintf("%x", x) != tt.x {
			t.Errorf("u = %s:\ngot x = %x,\nwant    %s", tt.u, x, tt.x)
		}
		if fmt.Sprintf("%x", y) != tt.y {
			t.Errorf("u = %s:\ngot y = %x,\nwant    %s", tt.u, y, tt.y)
		}
	}
}

func BenchmarkMapToCurve(b *testing.B) {
	b.ReportAllocs()
	u0, err := hex.DecodeString("4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee51adb29fec")
	if err != nil {
		b.Fatalf("u0: %v", err)
	}
	u1, err := hex.DecodeString("4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d20b4e269ee")
	if err != nil {
		b.Fatalf("u1: %v", err)
	}
	for i := 0; i < b.N; i++ {
		u := u0
		if uint(i)%2 == 1 {
			u = u1
		}
		_, err := nistec.P256MapToCurve(u)
		if err != nil {
			b.Fatalf("i=%d: %v", i, err)
		}
	}
}

func TestReduceBytes48(t *testing.T) {
	b := make([]byte, 48)
	for i := range b[16:] {
		b[16+i] = byte(i)
	}
	actual := nistec.TestReduceBytes48(b)
	expected := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if expected != fmt.Sprintf("%x", actual) {
		t.Errorf("\ngot %x\nwant %s", actual, expected)
	}

	b = make([]byte, 48)
	b[15] = 1
	actual = nistec.TestReduceBytes48(b)
	expected = "00000000fffffffeffffffffffffffffffffffff000000000000000000000001"
	if expected != fmt.Sprintf("%x", actual) {
		t.Errorf("\ngot %x\nwant %s", actual, expected)
	}

	b = make([]byte, 48)
	for i := range b {
		b[i] = 1
	}
	actual = nistec.TestReduceBytes48(b)
	expected = "fffffffefefefefffefefefefefefeff01010102030303030303030302020201"
	if expected != fmt.Sprintf("%x", actual) {
		t.Errorf("\ngot %x\nwant %s", actual, expected)
	}

	b = make([]byte, 48)
	for i := range b {
		b[i] = 0xff
	}
	actual = nistec.TestReduceBytes48(b)
	expected = "fffffffe00000001000000000000000200000002fffffffffffffffefffffffd"
	if expected != fmt.Sprintf("%x", actual) {
		t.Errorf("\ngot %x\nwant %s", actual, expected)
	}
}

func TestHashToCurve(t *testing.T) {
	//fmt.Printf("%x\n", expandMessage(nil, []byte("QUUX-V01-CS02-with-expander-SHA256-128"), 0x20))

	dst := []byte("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_")
	//b := expandMessage(nil, dst, 96)
	//p, err := nistec.HashToCurve(b)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Printf("%x", b)
	//t.Errorf("%x", p.Bytes()[1:])

	for _, tt := range []struct{ name, msg, x, y string }{
		{
			msg: "",
			x:   "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
			y:   "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
		},
		{
			msg: "abc",
			x:   "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
			y:   "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
		},
		{
			msg: "abcdef0123456789",
			x:   "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
			y:   "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
		},
		{
			name: "q128",
			msg:  "q128_" + strings.Repeat("q", 128),
			x:    "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
			y:    "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
		},
		{
			name: "a512",
			msg:  "a512_" + strings.Repeat("a", 512),
			x:    "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
			y:    "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
		},
	} {
		name := tt.name
		if name == "" {
			name = tt.msg
		}
		t.Run(name, func(t *testing.T) {
			expandedBytes := expandMessage([]byte(tt.msg), dst, 96)
			p, err := nistec.HashToCurve(expandedBytes)
			if err != nil {
				t.Errorf("MapToCurve failed: %v", err)
			}
			bytes := p.Bytes()
			x, y := bytes[1:33], bytes[33:]
			if fmt.Sprintf("%x", x) != tt.x {
				t.Errorf("bad x\ngot x = %x,\nwant    %s", x, tt.x)
			}
			if fmt.Sprintf("%x", y) != tt.y {
				t.Errorf("bad y\ngot y = %x,\nwant    %s", y, tt.y)
			}
		})
	}
}

func BenchmarkHashToCurve(b *testing.B) {
	b.ReportAllocs()
	dst := []byte("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_")
	msg := "a512_" + strings.Repeat("a", 512)
	expandedBytes := expandMessage([]byte(msg), dst, 96)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := nistec.HashToCurve(expandedBytes)
		if err != nil {
			b.Fatalf("i=%d: %v", i, err)
		}
	}
}

func expandMessage(msg []byte, DST []byte, size int) (out []byte) {
	h := sha256.New()
	h.Write(make([]byte, h.BlockSize()))
	h.Write(msg)
	h.Write([]byte{byte(size) >> 8, byte(size)})
	h.Write([]byte{0})
	h.Write(DST)
	dstLen := []byte{byte(len(DST))}
	h.Write(dstLen)
	b0 := h.Sum(nil)
	h.Reset()
	h.Write(b0)
	h.Write([]byte{1})
	h.Write(DST)
	h.Write(dstLen)
	bi := h.Sum(nil)
	out = make([]byte, 0, size)
	out = append(out, bi...)
	for i := 2; len(out) < size; i++ {
		h.Reset()
		for i := range bi {
			bi[i] ^= b0[i]
		}
		h.Write(bi)
		h.Write([]byte{byte(i)})
		h.Write(DST)
		h.Write(dstLen)
		h.Sum(bi[:0])
		out = append(out, bi...)
	}
	return out

}
