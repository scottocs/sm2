package main

import (
	"fmt"
	"github.com/scottocs/sm2/kdf"
)

var SM2_WORDSIZE int = 8
var SM2_NUMBITS int = 256
var SM2_NUMWORD int = 32
var ERR_ECURVE_INIT uint32 = 0x00000001
var ERR_INFINITY_POINT uint32 = 0x00000002
var ERR_NOT_VALID_POINT uint32 = 0x00000003
var ERR_ORDER uint32 = 0x00000004
var ERR_NOT_VALID_ELEMENT uint32 = 0x00000005
var ERR_GENERATE_R uint32 = 0x00000006
var ERR_GENERATE_S uint32 = 0x00000007
var ERR_OUTRANGE_R uint32 = 0x00000008
var ERR_OUTRANGE_S uint32 = 0x00000009
var ERR_GENERATE_T uint32 = 0x0000000A
var ERR_PUBKEY_INIT uint32 = 0x0000000B
var ERR_DATA_MEMCMP uint32 = 0x0000000C

var SM2_p=[32]uint8{0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff}
var SM2_a=[32]uint8{0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xfc}
var SM2_b=[32]uint8{0x28,0xe9,0xfa,0x9e, 0x9d,0x9f,0x5e,0x34, 0x4d,0x5a,0x9e,0x4b,0xcf,0x65,0x09,0xa7,
0xf3,0x97,0x89,0xf5, 0x15,0xab,0x8f,0x92, 0xdd,0xbc,0xbd,0x41,0x4d,0x94,0x0e,0x93}
var SM2_Gx=[32]uint8{0x32,0xc4,0xae,0x2c, 0x1f,0x19,0x81,0x19,0x5f,0x99,0x04,0x46,0x6a,0x39,0xc9,0x94,
0x8f,0xe3,0x0b,0xbf,0xf2,0x66,0x0b,0xe1,0x71,0x5a,0x45,0x89,0x33,0x4c,0x74,0xc7}
var SM2_Gy=[32]uint8{0xbc,0x37,0x36,0xa2,0xf4,0xf6,0x77,0x9c,0x59,0xbd,0xce,0xe3,0x6b,0x69,0x21,0x53,0xd0,
0xa9,0x87,0x7c,0xc6,0x2a,0x47,0x40,0x02,0xdf,0x32,0xe5,0x21,0x39,0xf0,0xa0}
var SM2_n=[32]uint8{0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0x72,0x03,0xdf,0x6b,0x21,0xc6,0x05,0x2b,0x53,0xbb,0xf4,0x09,0x39,0xd5,0x41,0x23}
var Gx,Gy,p,a,b,n kdf.Big
var G,nG *kdf.Epoint
var para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h kdf.Big

func SM2_Init () int {
	Gx = kdf.Mirvar(0)
	Gy = kdf.Mirvar(0)
	p = kdf.Mirvar(0)
	a = kdf.Mirvar(0)
	b = kdf.Mirvar(0)
	n = kdf.Mirvar(0)
	kdf.Bytes_to_big(SM2_NUMWORD, SM2_Gx[0:], Gx)
	kdf.Bytes_to_big(SM2_NUMWORD, SM2_Gy[0:], Gy)
	kdf.Bytes_to_big(SM2_NUMWORD, SM2_p[0:], p)
	kdf.Bytes_to_big(SM2_NUMWORD, SM2_a[0:], a)
	kdf.Bytes_to_big(SM2_NUMWORD, SM2_b[0:], b)
	kdf.Bytes_to_big(SM2_NUMWORD, SM2_n[0:], n)
	kdf.Ecurve_init(a, b, p, 0) //MR_PROJECTIVE为0？
	G = kdf.Epoint_init()
	nG = kdf.Epoint_init()
	para_a, para_b, para_n, para_p, para_Gx, para_Gy = a, b, n, p, Gx, Gy
	if kdf.Epoint_set(Gx, Gy, 0, G) == 0 { //initialise point G
		return int(ERR_ECURVE_INIT)
	}
	kdf.Ecurve_mult(n, G, nG)
	if kdf.Point_at_infinity(nG) == 0 {
		//test if the order of the point is n
		return int(ERR_ORDER)
	}
	return 0
}

//func Test_Point(point *kdf.Epoint)int {
//	var x, y, x_3, tmp kdf.Big
//	x = kdf.Mirvar(0)
//	y = kdf.Mirvar(0)
//	x_3 = kdf.Mirvar(0)
//	tmp = kdf.Mirvar(0)
//	//test if y^2=x^3+ax+b
//	kdf.Epoint_get(point, x, y)
//	Power(x, 3, p, x_3) //x_3=x^3 mod p
//	kdf.Multiply(x, a, x)   //x=a*x
//	kdf.Divide(x, p, tmp)   //x=a*x mod p , tmp=a*x/p
//	kdf.Add(x_3, x, x)      //x=x^3+ax
//	kdf.Add(x, b, x)        //x=x^3+ax+b
//	kdf.Divide(x, p, tmp)   //x=x^3+ax+b mod p
//	Power(y, 2, p, y)   //y=y^2 mod p
//	if kdf.Compare(x, y) != 0 {
//		return int(ERR_NOT_VALID_POINT)
//	} else {
//return 0}
//}


//func Test_PubKey(pubKey *kdf.Epoint)int {
//	var x, y, x_3, tmp kdf.Big
//	var nP *kdf.Epoint
//	x = kdf.Mirvar(0)
//	y = kdf.Mirvar(0)
//	x_3 = kdf.Mirvar(0)
//	tmp = kdf.Mirvar(0)
//	nP = kdf.Epoint_init()
//	//test if the pubKey is the point at infinity
//	if Point_at_infinity(pubKey) != 0 {
//		// if pubKey is point at infinity, return error;
//		return int(ERR_INFINITY_POINT)
//	}
//	//test if x<p and y<p both hold
//	kdf.Epoint_get(pubKey, x, y)
//	if (kdf.Compare(x, p) != -1) || (kdf.Compare(y, p) != -1) {
//		return int(ERR_NOT_VALID_ELEMENT)
//	}
//	if Test_Point(pubKey) != 0 {
//		return int(ERR_NOT_VALID_POINT)
//	}
//	//test if the order of pubKey is equal to n
//	kdf.Ecurve_mult(n, pubKey, nP) // nP=[n]P
//	if Point_at_infinity(nP) == 0 { // if np is point NOT at infinity, return error;
//		return int(ERR_ORDER)
//	}
//	return 0
//}

func Test_Zero(x kdf.Big) int {
	var zero kdf.Big
	zero = kdf.Mirvar(0)
	if kdf.Compare(x, zero) == 0 {
		return 1
	} else {
		return 0
	}
}

func Test_n(x kdf.Big)int {
	// kdf.Bytes_to_big(32,SM2_n,n);
	if kdf.Compare(x, n) == 0 {
		return 1
	} else {
		return 0
	}
}

func Test_Range(x kdf.Big)int {
	var one, decr_n kdf.Big
	one = kdf.Mirvar(0)
	decr_n = kdf.Mirvar(0)
	kdf.convert(1, one)
	kdf.decr(n, 1, decr_n)
	if (kdf.Compare(x, one) < 0) || (kdf.Compare(x, decr_n) > 0) { //这里原本是(kdf.Compare(x, one) < 0) | (kdf.Compare(x, decr_n) > 0)
		return 1
	}
	return 0
}

func SM2_KeyGeneration(PriKey[]uint8,Px[]uint8,Py[]uint8)int {
	var i int = 0
	var d, PAx, PAy kdf.Big
	var PA *kdf.Epoint
	SM2_Init()
	PA = kdf.Epoint_init()
	d = kdf.Mirvar(0)
	PAx = kdf.Mirvar(0)
	PAy = kdf.Mirvar(0)
	kdf.Bytes_to_big(SM2_NUMWORD, PriKey, d)
	kdf.Ecurve_mult(d, G, PA)
	kdf.Epoint_get(PA, PAx, PAy)
	kdf.Big_to_bytes(SM2_NUMWORD, PAx, Px, true)
	kdf.Big_to_bytes(SM2_NUMWORD, PAy, Py, true)
	i = int(kdf.Test_PubKey(PA))
	if i != 0 {
		return i
	} else {
		return 0
	}
}

func SM2_Sign(message []uint8,len int,ZA[]uint8,rand[]uint8,d[]uint8,R[]uint8,S[]uint8)int {
	var hash [32]uint8
	var M_len int = len + int(kdf.SM3_len)/8
	var M []uint8 = nil
	var i int
	var dA, r, s, e, k, KGx, KGy kdf.Big
	var rem, rk, z1, z2 kdf.Big
	var KG *kdf.Epoint
	i = SM2_Init()
	if i != 0 {
		return i
	}
	//initiate
	dA = kdf.Mirvar(0)
	e = kdf.Mirvar(0)
	k = kdf.Mirvar(0)
	KGx = kdf.Mirvar(0)
	KGy = kdf.Mirvar(0)
	r = kdf.Mirvar(0)
	s = kdf.Mirvar(0)
	rem = kdf.Mirvar(0)
	rk = kdf.Mirvar(0)
	z1 = kdf.Mirvar(0)
	z2 = kdf.Mirvar(0)
	kdf.Bytes_to_big(SM2_NUMWORD, d, dA) //cinstr(dA,d);
	KG = kdf.Epoint_init()
	//step1,set M=ZA||M
	//M = (char *)malloc(sizeof(char) * (M_len + 1)) 记号
	M = make([]uint8,M_len+1)
	kdf.Memcpy(M, ZA, int(kdf.SM3_len)/8)
	kdf.Memcpy(M[kdf.SM3_len/8:], message, len)
	//step2,generate e=H(M)
	kdf.SM3_256(M, M_len, hash[:])
	kdf.Bytes_to_big(int(kdf.SM3_len)/8, hash[:], e)
	//step3:generate k
	kdf.Bytes_to_big(int(kdf.SM3_len)/8, rand, k)
	//step4:calculate kG
	kdf.Ecurve_mult(k, G, KG)
	//step5:calculate r
	kdf.Epoint_get(KG, KGx, KGy)
	kdf.Add(e, KGx, r)
	kdf.Divide(r, n, rem)
	//judge r=0 or n+k=n?
	kdf.Add(r, k, rk)
	if Test_Zero(r)!=0 || Test_n(rk)!=0 {
		return int(ERR_GENERATE_R)
	}
	//step6:generate s
	kdf.Incr(dA, 1, z1)
	kdf.Xgcd(z1, n, z1, z1, z1)
	kdf.Multiply(r, dA, z2)
	kdf.Divide(z2, n, rem)
	kdf.Subtract(k, z2, z2)
	kdf.Add(z2, n, z2)
	kdf.Multiply(z1, z2, s)
	kdf.Divide(s, n, rem)
	//judge s=0?
	if Test_Zero(s)!=0 {
		return int(ERR_GENERATE_S)
	}
	kdf.Big_to_bytes(SM2_NUMWORD, r, R, true)
	kdf.Big_to_bytes(SM2_NUMWORD, s, S, true)
	//free(M);
	return 0
}

func SM2_Verify(message []uint8,len int,ZA[]uint8,Px[]uint8,Py[]uint8,R[]uint8,S[]uint8)int {
	var hash [32]uint8
	var M_len int = len + int(kdf.SM3_len)/8
	var M []uint8 = nil
	var i int
	var PAx, PAy, r, s, e, t, rem, x1, y1, RR kdf.Big
	var PA, sG, tPA *kdf.Epoint
	i = SM2_Init()
	if i != 0 {
		return i
	}
	PAx = kdf.Mirvar(0)
	PAy = kdf.Mirvar(0)
	r = kdf.Mirvar(0)
	s = kdf.Mirvar(0)
	e = kdf.Mirvar(0)
	t = kdf.Mirvar(0)
	x1 = kdf.Mirvar(0)
	y1 = kdf.Mirvar(0)
	rem = kdf.Mirvar(0)
	RR = kdf.Mirvar(0)
	PA = kdf.Epoint_init()
	sG = kdf.Epoint_init()
	tPA = kdf.Epoint_init()
	kdf.Bytes_to_big(SM2_NUMWORD, Px, PAx)
	kdf.Bytes_to_big(SM2_NUMWORD, Py, PAy)
	kdf.Bytes_to_big(SM2_NUMWORD, R, r)
	kdf.Bytes_to_big(SM2_NUMWORD, S, s)
	if kdf.Epoint_set(PAx, PAy, 0, PA) == 0 { //initialise public key
		return int(ERR_PUBKEY_INIT)
	}
	//step1: test if r belong to [1,n-1]
	if Test_Range(r)!=0 {
		return int(ERR_OUTRANGE_R)
	}
	//step2: test if s belong to [1,n-1]
	if Test_Range(s)!=0 {
		return int(ERR_OUTRANGE_S)
	}
	//step3,generate M
	M = make([]uint8,M_len+1)
	kdf.Memcpy(M, ZA, 32)
	kdf.Memcpy(M[32:], message, len)
	//step4,generate e=H(M)
	kdf.SM3_256(M, M_len, hash[:])
	kdf.Bytes_to_big(int(kdf.SM3_len)/8, hash[:], e)
	//step5:generate t
	kdf.Add(r, s, t)
	kdf.Divide(t, n, rem)
	if Test_Zero(t)!=0 {
		return int(ERR_GENERATE_T)
	}
	//step 6: generate(x1,y1)
	kdf.Ecurve_mult(s, G, sG)
	kdf.Ecurve_mult(t, PA, tPA)
	kdf.Ecurve_add(sG, tPA)
	kdf.Epoint_get(tPA, x1, y1)
	//step7:generate RR
	kdf.Add(e, x1, RR)
	kdf.Divide(RR, n, rem)
	//free(M);
	if kdf.Compare(RR, r) == 0 {
		return 0
	} else {
		return int(ERR_DATA_MEMCMP)
	}
}

func main(){
	SM2_SelfCheck()
}
func SM2_SelfCheck()int {
	//the private key
	var dA = [32]uint8{0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f,
					   0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8}
	var rand = [32]uint8{0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D,
						 0xCC, 0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21}
	//the public key
	 var xA=[32]uint8{0x09,0xf9,0xdf,0x31,0x1e,0x54,0x21,0xa1,0x50,0xdd,0x7d,0x16,0x1e,0x4b,0xc5,
0xc6,0x72,0x17,0x9f,0xad,0x18,0x33,0xfc,0x07,0x6b,0xb0,0x8f,0xf3,0x56,0xf3,0x50,0x20};
var yA=[32]uint8{0xcc,0xea,0x49,0x0c,0xe2,0x67,0x75,0xa5,0x2d,0xc6,0xea,0x71,0x8c,0xc1,0xaa,
0x60,0x0a,0xed,0x05,0xfb,0xf3,0x5e,0x08,0x4a,0x66,0x32,0xf6,0x07,0x2d,0xa9,0xad,0x13};
	//var xA [32]uint8
	//var yA [32]uint8
	var r [32]uint8
	var s [32]uint8 // Signature424C 49 43 45 31 32 33 40 59 41 48 4F 4F 2E 43 4F 11
	var IDA = [18]uint8{0x42, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33, 0x40, 0x59, 0x41,
						0x48, 0x4F, 0x4F, 0x2E, 0x43, 0x4F,0x11} //ASCII code of userA's identification
	var IDA_len int = 18
	var ENTLA = [2]uint8{0x00, 0x90}      //the length of userA's identification,presentation in ASCII code
	str := "message digest"
	var message =[]uint8(str) //the message to be signed
	var len int = len(message)         //the length of message
	var ZA [32]uint8                  //ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	N := IDA_len+2+SM2_NUMWORD*6
	var Msg = make([]uint8,N,N)                         //210=IDA_len+2+SM2_NUMWORD*6
	var temp int
	var mip *kdf.Miracl = kdf.Mirsys(10000, 16)
	mip.IOBASE = 16
	temp = SM2_KeyGeneration(dA[:], xA[:], yA[:])
	if temp != 0 {
		return temp
	}
	// ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA
	kdf.Memcpy(Msg[:], ENTLA[:], 2)
	kdf.Memcpy(Msg[2:N], IDA[:], IDA_len)
	kdf.Memcpy(Msg[2+IDA_len:N], SM2_a[:], SM2_NUMWORD)
	kdf.Memcpy(Msg[2+IDA_len+SM2_NUMWORD:N], SM2_b[:], SM2_NUMWORD)
	kdf.Memcpy(Msg[2+IDA_len+SM2_NUMWORD*2:N], SM2_Gx[:], SM2_NUMWORD)
	kdf.Memcpy(Msg[2+IDA_len+SM2_NUMWORD*3:N], SM2_Gy[:], SM2_NUMWORD)
	kdf.Memcpy(Msg[2+IDA_len+SM2_NUMWORD*4:N], xA[:], SM2_NUMWORD)
	kdf.Memcpy(Msg[2+IDA_len+SM2_NUMWORD*5:N], yA[:], SM2_NUMWORD)
	kdf.SM3_256(Msg[:], N, ZA[:])
	temp = SM2_Sign(message, len, ZA[:], rand[:], dA[:], r[:], s[:])
	if temp != 0 {
		fmt.Print("s")
		return temp
	}
	temp = SM2_Verify(message, len, ZA[:], xA[:], yA[:], r[:], s[:])
	if temp != 0 {
		fmt.Print("s")
		return temp
	}
	fmt.Printf("%x\n",ZA)
	fmt.Printf("%x\n",r)
	fmt.Printf("%x\n",s)
	return 0
}
