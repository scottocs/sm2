//2017年7月23日16:02:55 czn
package main

import (
	"encoding/binary"
)

var SM3_len uint32 = 256
var SM3_t1 uint32 = 0x79cc4519
var SM3_t2 uint32 = 0x7a879d8a
var SM3_iva uint32 = 0x7380166f
var SM3_ivb uint32 = 0x4914b2b9
var SM3_ivc uint32 = 0x172442d7
var SM3_ivd uint32 = 0xda8a0600
var SM3_ive uint32 = 0xa96f30bc
var SM3_ivf uint32 = 0x163138aa
var SM3_ivg uint32 = 0xe38dee4d
var SM3_ivh uint32 = 0xb0fb0e4e

func SM3_rotl32(x, y uint32) uint32 {
	return (x << y) | (x >> (32 - y))
}

/*func SM3_rotr32(x ,y uint32) uint32{
	return (x >> y) | (x << (32 - y))
}*/

func SM3_p1(x uint32) uint32 {
	return x ^ SM3_rotl32(x, 15) ^ SM3_rotl32(x, 23)
}

func SM3_p0(x uint32) uint32 {
	return x ^ SM3_rotl32(x, 9) ^ SM3_rotl32(x, 17)
}

func SM3_ff0(a, b, c uint32) uint32 {
	return a ^ b ^ c
}

func SM3_ff1(a, b, c uint32) uint32 {
	return (a & b) | (a & c) | (b & c)
}

func SM3_gg0(a, b, c uint32) uint32 {
	return a ^ b ^ c
}

func SM3_gg1(a, b, c uint32) uint32 {
	return (a & b) | ((^a) & c)
}

type SM3_STATE struct {
	state  [8]uint32
	length uint32
	curlen uint32
	buf    [64]uint8
}

func bitow(bi []uint8, w [68]uint32) [68]uint32 {
	var tmp uint32
	var i int = 0
	var bi32 = make([]uint32, 16, 16)
	for i != 16 {
		bi32[i] = binary.LittleEndian.Uint32([]byte(bi[4*i : 4*i+4]))
		i++
	}
	for i = 0; i <= 15; i++ {
		w[i] = bi32[i]
	}
	for i = 16; i <= 67; i++ {
		tmp = w[i-16] ^ w[i-9] ^ SM3_rotl32(w[i-3], 15)
		w[i] = SM3_p1(tmp) ^ SM3_rotl32(w[i-13], 7) ^ w[i-6]
	}
	return w
}

func wtow1(w [68]uint32, w1 [64]uint32) ([68]uint32, [64]uint32) {
	var i int

	for i = 0; i <= 63; i++ {
		w1[i] = w[i] ^ w[i+4]
	}
	return w, w1
}

func cf(w [68]uint32, w1 [64]uint32, v [8]uint32) [8]uint32 {
	var ss1 uint32
	var ss2 uint32
	var tt1 uint32
	var tt2 uint32
	var a, b, c, d, e, f, g, h uint32
	var t uint32 = SM3_t1
	var ff, gg uint32
	var j int

	a = v[0]
	b = v[1]
	c = v[2]
	d = v[3]
	e = v[4]
	f = v[5]
	g = v[6]
	h = v[7]

	for j = 0; j <= 63; j++ {
		if j == 0 {
			t = SM3_t1
		} else if j == 16 {
			t = SM3_rotl32(SM3_t2, 16)
		} else {
			t = SM3_rotl32(t, 1)
		}

		ss1 = SM3_rotl32((SM3_rotl32(a, 12) + e + t), 7)

		ss2 = ss1 ^ SM3_rotl32(a, 12)

		if j <= 15 {
			ff = SM3_ff0(a, b, c)
		} else {
			ff = SM3_ff1(a, b, c)
		}
		tt1 = ff + d + ss2 + w1[j]

		if j <= 15 {
			gg = SM3_gg0(e, f, g)
		} else {
			gg = SM3_gg1(e, f, g)
		}
		tt2 = gg + h + ss1 + w[j]

		d = c
		c = SM3_rotl32(b, 9)
		b = a
		a = tt1
		h = g
		g = SM3_rotl32(f, 19)
		f = e
		e = SM3_p0(tt2)
	}

	v[0] = a ^ v[0]
	v[1] = b ^ v[1]
	v[2] = c ^ v[2]
	v[3] = d ^ v[3]
	v[4] = e ^ v[4]
	v[5] = f ^ v[5]
	v[6] = g ^ v[6]
	v[7] = h ^ v[7]
	return v
}

func bigendian(src []uint8, bytelen uint32, des []uint8){
	var tmp uint8 = 0
	var i uint32 = 0

	for i = 0; i < bytelen/4; i++ {
		tmp = des[4*i]
		des[4*i] = src[4*i+3]
		src[4*i+3] = tmp

		tmp = des[4*i+1]
		des[4*i+1] = src[4*i+2]
		des[4*i+2] = tmp
	}
}

func SM3_init(md *SM3_STATE) {
	md.curlen = 0
	md.length = 0
	md.state[0] = SM3_iva
	md.state[1] = SM3_ivb
	md.state[2] = SM3_ivc
	md.state[3] = SM3_ivd
	md.state[4] = SM3_ive
	md.state[5] = SM3_ivf
	md.state[6] = SM3_ivg
	md.state[7] = SM3_ivh
}


func SM3_compress(md *SM3_STATE) {
	var w [68]uint32
	var w1 [64]uint32
	bigendian(md.buf[:], 64, md.buf[:])
	w = bitow(md.buf[:], w)
	w, w1 = wtow1(w, w1)
	md.state = cf(w, w1, md.state)
}

func SM3_process(md *SM3_STATE, buf []uint8, len int) {
	var i int
	for i = 0; len != 0; len-- {
		md.buf[md.curlen] = buf[i]
		i++
		md.curlen++

		if md.curlen == 64 {
			SM3_compress(md)
			md.length += 512
			md.curlen = 0
		}
	}
}

func SM3_done(md *SM3_STATE, hash []uint8) []uint8 {
	var i int
	var tmp = make([]uint8, 4, 4)
	md.length += md.curlen << 3

	md.buf[md.curlen] = 0x80
	md.curlen++

	if md.curlen > 56 {
		for md.curlen < 64 {
			md.buf[md.curlen] = 0
			md.curlen++
		}
		SM3_compress(md)
		md.curlen = 0
	}

	for md.curlen < 56 {
		md.buf[md.curlen] = 0
		md.curlen++
	}

	for i = 56; i < 60; i++ {
		md.buf[i] = 0
	}

	md.buf[63] = uint8(md.length & 0xff)
	md.buf[62] = uint8(md.length >> 8 & 0xff)
	md.buf[61] = uint8(md.length >> 16 & 0xff)
	md.buf[60] = uint8(md.length >> 24 & 0xff)

	SM3_compress(md)

	for i = 0; i != 8; i++ {
		binary.BigEndian.PutUint32(tmp, md.state[i])
		hash[4*i] = tmp[0]
		hash[4*i+1] = tmp[1]
		hash[4*i+2] = tmp[2]
		hash[4*i+3] = tmp[3]
	}
	return hash
}

func SM3_256(buf []uint8, len int, hash []uint8) []uint8 {
	var md SM3_STATE
	SM3_init(&md)
	SM3_process(&md, buf, len)
	hash = SM3_done(&md, hash)
	return hash
}

func SM3_KDF(Z []uint8, zlen uint32, klen uint32, K []uint8) {
	var i,j,  t uint32
	var bitklen uint32
	var md SM3_STATE
	var Ha [32]uint8
	var ct = [4]uint8{0, 0, 0, 1}
	bitklen = klen * 8
	if bitklen % 256 != 0{
		t = bitklen/256 + 1
	} else {
		t = bitklen / 256
	}
	//s4: K=Ha1||Ha2||...
	for i = 1; i < t; i++ {
		//s2: Hai=Hv(Z||ct)
		SM3_init(&md)
		SM3_process(&md, Z, int(zlen))
		SM3_process(&md, ct[0:], 4)
		SM3_done(&md, Ha[0:])
		memcpy(K[32*(i-1):], Ha[:], 32)
		if ct[3] == 0xff {
			ct[3] = 0
			if ct[2] == 0xff {
				ct[2] = 0
				if ct[1] == 0xff {
					ct[1] = 0
					ct[0]++
				} else {
					ct[1]++
				}
			} else {
				ct[2]++
			}
		} else {
			ct[3]++
		}
	}
	//s3: klen/v非整数的处理
	SM3_init(&md)
	SM3_process(&md, Z, int(zlen))
	SM3_process(&md, ct[0:], 4)
	SM3_done(&md, Ha[0:])
	if bitklen % 256!=0 {
		i = (256 - bitklen + 256*(bitklen/256)) / 8
		j = (bitklen - 256*(bitklen/256)) / 8
		memcpy(K[32*(t-1):], Ha[:], int(j))
	} else {
		memcpy(K[32*(t-1):], Ha[:], 32)
	}
}
