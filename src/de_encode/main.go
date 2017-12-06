package main

import "fmt"

var ECC_WORDSIZE uint32 = 8
var SM2_NUMBITS int = 256
var SM2_NUMWORD int = 32
var ERR_INFINITY_POINT uint32 = 0x00000001
var ERR_NOT_VALID_ELEMENT uint32 = 0x00000002
var ERR_NOT_VALID_POINT uint32 = 0x00000003
var ERR_ORDER uint32 = 0x00000004
var ERR_ARRAY_NULL uint32 = 0x00000005
var ERR_C3_MATCH uint32 = 0x00000006
var ERR_Ecurve_INIT uint32 = 0x00000007
var ERR_SELFTEST_KG uint32 = 0x00000008
var ERR_SELFTEST_ENC uint32 = 0x00000009
var ERR_SELFTEST_DEC uint32 = 0x0000000A

var SM2_p  =[32]uint8  {0x85,0x42,0xd6,0x9e,0x4c,0x04,0x4F,0x18,0xe8,0xb9,0x24,0x35,0xbf,0x6f,0xf7,0xde,
0x45,0x72,0x83,0x91,0x5c,0x45,0x51,0x7d,0x72,0x2e,0xdb,0x8b,0x08,0xF1,0xdF,0xc3}
var SM2_a = [32]uint8 {0x78,0x79,0x68,0xb4,0xfa,0x32,0xc3,0xFd,0x24,0x17,0x84,0x2e,0x73,0xbb,0xFe,0xFF,
0x2F,0x3c,0x84,0x8b,0x68,0x31,0xd7,0xe0,0xec,0x65,0x22,0x8b,0x39,0x37,0xe4,0x98}
var SM2_b = [32]uint8 {0x63,0xE4,0xc6,0xd3,0xb2,0x3b,0x0c,0x84,0x9c,0xf8,0x42,0x41,0x48,0x4b,0xfe,0x48,
0xF6,0x1d,0x59,0xa5,0xb1,0x6B,0xa0,0x6e,0x6e,0x12,0xD1,0xda,0x27,0xc5,0x24,0x9a}
var SM2_n = [32]uint8 {0x85,0x42,0xD6,0x9E,0x4C,0x04,0x4F,0x18,0xE8,0xB9,0x24,0x35,0xBF,0x6F,0xF7,0xDD,
	0x29,0x77,0x20,0x63,0x04,0x85,0x62,0x8D,0x5A,0xE7,0x4E,0xE7,0xC3,0x2E,0x79,0xB7}
var SM2_Gx = [32]uint8 {0x42,0x1D,0xEB,0xD6,0x1B,0x62,0xEA,0xB6,0x74,0x64,0x34,0xEB,0xC3,0xCC,0x31,0x5E,
	0x32,0x22,0x0B,0x3B,0xAD,0xD5,0x0B,0xDC,0x4C,0x4E,0x6C,0x14,0x7F,0xED,0xD4,0x3D}
var SM2_Gy = [32]uint8 {0x06,0x80,0x51,0x2B,0xCB,0xB4,0x2C,0x07,0xD4,0x73,0x49,0xD2,0x15,0x3B,0x70,0xC4,
	0xE5,0xD7,0xFD,0xFC,0xBF,0xA3,0x6E,0xA1,0xA8,0x58,0x41,0xB9,0xE4,0x6E,0x09,0xA2}
var SM2_h = [32]uint8 {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01}
var para_p,para_a,para_b,para_n,para_Gx,para_Gy,para_h Big
var G *Epoint
var mip *Miracl

//func Test_Point(point *Epoint) uint32 {
//	var x, y, x_3, tmp Big
//	x = Mirvar(0)
//	y = Mirvar(0)
//	x_3 = Mirvar(0)
//	tmp = Mirvar(0)
//	//test if y^2=x^3+ax+b
//	Epoint_get(point, x, y)
//	Power(x, 3, para_p, x_3) //x_3=x^3 mod p
//	Multiply(x, para_a, x)   //x=a*x
//	Divide(x, para_p, tmp)   //x=a*x mod p , tmp=a*x/p
//	Add(x_3, x, x)           //x=x^3+ax
//	Add(x, para_b, x)        //x=x^3+ax+b
//	Divide(x, para_p, tmp)   //x=x^3+ax+b mod p
//	Power(y, 2, para_p, y)   //y=y^2 mod p
//	if compare(x, y) != 0 {
//		return ERR_NOT_VALID_POINT
//	} else {
//		return 0}
//}
//
//func Test_PubKey(pubKey *Epoint) uint32 {
//	var x, y, x_3, tmp Big
//	var nP *Epoint
//	x = Mirvar(0)
//	y = Mirvar(0)
//	x_3 = Mirvar(0)
//	tmp = Mirvar(0)
//	nP = Epoint_init()
//	//test if the pubKey is the point at infinity
//	if Point_at_infinity(pubKey) { // if pubKey is point at infinity, return error;
//		return ERR_INFINITY_POINT
//	}
//	//test if x<p and y<p both hold
//	Epoint_get(pubKey, x, y)
//	if (compare(x, para_p) != -1) || (compare(y, para_p) != -1) {
//		return ERR_NOT_VALID_ELEMENT
//	}
//	if Test_Point(pubKey) != 0 {
//		return ERR_NOT_VALID_POINT
//	}
//	//test if the order of pubKey is equal to n
//	Ecurve_mult(para_n, pubKey, nP) // nP=[n]P
//	if Point_at_infinity(nP) == 0 { // if np is point NOT at infinity, return error;
//		return ERR_ORDER
//	}
//	return 0
//}

func Test_Null(array []uint8,len int) int {
	var i int = 0
	for i = 0; i < len; i++ {
		if array[i] != 0x00 {
			return 0
		}
	}
	return 1
}

func SM2_Init() uint32 {
	var nG *Epoint
	para_p = Mirvar(0)
	para_a = Mirvar(0)
	para_b = Mirvar(0)
	para_n = Mirvar(0)
	para_Gx = Mirvar(0)
	para_Gy = Mirvar(0)
	para_h = Mirvar(0)
	G = Epoint_init()
	nG = Epoint_init()
	Bytes_to_big(SM2_NUMWORD, SM2_p[:], para_p)
	Bytes_to_big(SM2_NUMWORD, SM2_a[:], para_a)
	Bytes_to_big(SM2_NUMWORD, SM2_b[:], para_b)
	Bytes_to_big(SM2_NUMWORD, SM2_n[:], para_n)
	Bytes_to_big(SM2_NUMWORD, SM2_Gx[:], para_Gx)
	Bytes_to_big(SM2_NUMWORD, SM2_Gy[:], para_Gy)
	Bytes_to_big(SM2_NUMWORD, SM2_h[:], para_h)
	ecurve_init(para_a, para_b, para_p,0)
	//Initialises GF(p) elliptic curve.
	//MR_PROJECTIVE specifying projective coordinates
	if Epoint_set(para_Gx, para_Gy, 0, G) == 0 { //initialise point G
		return ERR_Ecurve_INIT
	}
	Ecurve_mult(para_n, G, nG)
	if Point_at_infinity(nG)==0 { //test if the order of the point is n
		return ERR_ORDER
	}
	return 0
}

func SM2_KeyGeneration(priKey Big,pubKey *Epoint)int {
	var x, y Big
	x = Mirvar(0)
	y = Mirvar(0)
	Ecurve_mult(priKey, G, pubKey) //通过大数和基点产生公钥
	Epoint_get(pubKey, x, y)
	if Test_PubKey(pubKey) != 0 {
		return 1
	} else {
		return 0
	}
}

func SM2_Encrypt(randK []uint8,pubKey *Epoint,M[] uint8,klen int,C[] uint8) uint32 {
	var C1x, C1y, x2, y2, rand Big
	var C1, kP, S *Epoint
	var i int = 0
	var x2y2 = [64]uint8{0}
	var md SM3_STATE
	C1x = Mirvar(0)
	C1y = Mirvar(0)
	x2 = Mirvar(0)
	y2 = Mirvar(0)
	rand = Mirvar(0)
	C1 = Epoint_init()
	kP = Epoint_init()
	S = Epoint_init()
	//Step2. calculate C1=[k]G=(rGx,rGy)
	Bytes_to_big(SM2_NUMWORD, randK, rand)
	Ecurve_mult(rand, G, C1) //C1=[k]G
	Epoint_get(C1, C1x, C1y)
	Big_to_bytes(SM2_NUMWORD, C1x, C, true)
	Big_to_bytes(SM2_NUMWORD, C1y, C[SM2_NUMWORD:], true)
	//Step3. test if S=[h]pubKey if the point at infinity
	Ecurve_mult(para_h, pubKey, S)
	if Point_at_infinity(S)!=0 { // if S is point at infinity, return error;
		return ERR_INFINITY_POINT
	}
	//Step4. calculate [k]PB=(x2,y2)
	Ecurve_mult(rand, pubKey, kP) //kP=[k]P
	Epoint_get(kP, x2, y2)
	//Step5. KDF(x2||y2,klen)
	Big_to_bytes(SM2_NUMWORD, x2, x2y2[:], true)
	Big_to_bytes(SM2_NUMWORD, y2, x2y2[SM2_NUMWORD:], true)
	SM3_KDF(x2y2[:], 64, uint32(klen), C[SM2_NUMWORD*2:])
	if Test_Null(C[SM2_NUMWORD*2:], klen) != 0 {
		return ERR_ARRAY_NULL
	}
	//Step6. C2=M^t
	for i = 0; i < klen; i++ {
		C[SM2_NUMWORD*2+i] = M[i] ^ C[SM2_NUMWORD*2+i]
	}
	//Step7. C3=hash(x2,M,y2)
	SM3_init(&md)
	SM3_process(&md, x2y2[:], SM2_NUMWORD)
	SM3_process(&md, M, klen)
	SM3_process(&md, x2y2[SM2_NUMWORD:], SM2_NUMWORD)
	SM3_done(&md, C[SM2_NUMWORD*2+klen:])
	return 0
}

func SM2_Decrypt(dB Big,C[] uint8,Clen int,klen int,M[] uint8)uint32 {
	var md SM3_STATE
	var i uint32 = 0
	var x2y2 = [64]uint8{0}
	var hash = [32]uint8{0}
	var C1x, C1y, x2, y2 Big
	var C1, S, dBC1 *Epoint
	C1x = Mirvar(0)
	C1y = Mirvar(0)
	x2 = Mirvar(0)
	y2 = Mirvar(0)
	C1 = Epoint_init()
	S = Epoint_init()
	dBC1 = Epoint_init()
	//Step1. test if C1 fits the curve
	Bytes_to_big(SM2_NUMWORD, C, C1x)
	Bytes_to_big(SM2_NUMWORD, C[SM2_NUMWORD:], C1y)
	Epoint_set(C1x, C1y, 0, C1)
	i = Test_Point(C1)
	if i != 0 {
		return i
	}
	//Step2. S=[h]C1 and test if S is the point at infinity
	Ecurve_mult(para_h, C1, S)
	if Point_at_infinity(S)!=0 { // if S is point at infinity, return error;
		return ERR_INFINITY_POINT
	}
	//Step3. [dB]C1=(x2,y2)
	Ecurve_mult(dB, C1, dBC1)
	Epoint_get(dBC1, x2, y2)
	Big_to_bytes(SM2_NUMWORD, x2, x2y2[:], true)
	Big_to_bytes(SM2_NUMWORD, y2, x2y2[SM2_NUMWORD:], true)
	//Step4. t=KDF(x2||y2,klen)
	SM3_KDF(x2y2[:], uint32(SM2_NUMWORD*2), uint32(klen), M)
	if Test_Null(M, klen) != 0 {
		return ERR_ARRAY_NULL
	}
	//Step5. M=C2^t
	for i = 0; i < uint32(klen); i++ {
		M[i] = M[i] ^ C[uint32(SM2_NUMWORD*2)+i]
	}
	//Step6. hash(x2,m,y2)
	SM3_init(&md)
	SM3_process(&md, x2y2[:], SM2_NUMWORD)
	SM3_process(&md, M, klen)
	SM3_process(&md, x2y2[SM2_NUMWORD:], SM2_NUMWORD)
	SM3_done(&md, hash[:])
	if memcmp(hash[:],C[SM2_NUMWORD*2+klen:],SM2_NUMWORD)!=0 {
		return ERR_C3_MATCH
	} else {
		return 0}
}

func SM2_ENC_SelfTest()uint32 {
	var tmp int = 0
	var Cipher = [115]uint8{0}
	var M = [19]uint8{0}
	var kGxy = [64]uint8{0}
	var ks, x, y Big
	var kG *Epoint
	//standard data
	var std_priKey = [32]uint8{0x16,0x49,0xAB,0x77,0xA0,0x06,0x37,0xBD,0x5E,0x2E,0xFE,0x28,0x3F,0xBF,0x35,0x35,0x34,0xAA,0x7F,
		0x7C,0xB8,0x94,0x63,0xF2,0x08,0xDD,0xBC,0x29,0x20,0xBB,0x0D,0xA0}
	var std_pubKey = [64]uint8{0x43,0x5B,0x39,0xCC,0xA8,0xF3,0xB5,0x08,0xC1,0x48,0x8A,0xFC,0x67,0xBE,0x49,0x1A,0x0F,0x7B,0xA0,
		0x7E,0x58,0x1A,0x0E,0x48,0x49,0xA5,0xCF,0x70,0x62,0x8A,0x7E,0x0A,0x75,0xDD,0xBA,0x78,0xF1,0x5F,0xEE,0xCB,0x4C,0x78,0x95,
		0xE2,0xC1,0xCD,0xF5,0xFE,0x01,0xDE,0xBB,0x2C,0xDB,0xAD,0xF4,0x53,0x99,0xCC,0xF7,0x7B,0xBA,0x07,0x6A,0x42}
	var std_rand = [32]uint8{0x4C,0x62,0xEE,0xFD,0x6E,0xCF,0xC2,0xB9,0x5B,0x92,0xFD,0x6C,0x3D,0x95,0x75,0x14,0x8A,0xFA,
		0x17,0x42,0x55,0x46,0xD4,0x90,0x18,0xE5,0x38,0x8D,0x49,0xDD,0x7B,0x4F}
	var std_Message = [19]uint8{0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E,
								0x64, 0x61, 0x72, 0x64}
	var std_Cipher = [115]uint8{0x24,0x5C,0x26,0xFB,0x68,0xB1,0xDD,0xDD,0xB1,0x2C,0x4B,0x6B,0xF9,0xF2,0xB6,0xD5,
		0xFE,0x60,0xA3,0x83,0xB0,0xD1,0x8D,0x1C,0x41,0x44,0xAB,0xF1,0x7F,0x62,0x52,0xE7,0x76,0xCB,0x92,0x64,0xC2,0xA7,
		0xE8,0x8E,0x52,0xB1,0x99,0x03,0xFD,0xC4,0x73,0x78,0xF6,0x05,0xE3,0x68,0x11,0xF5,0xC0,0x74,0x23,0xA2,0x4B,0x84,
		0x40,0x0F,0x01,0xB8,0x65,0x00,0x53,0xA8,0x9B,0x41,0xC4,0x18,0xB0,0xC3,0xAA,0xD0,0x0D,0x88,0x6C,0x00,0x28,0x64,
		0x67,0x9C,0x3D,0x73,0x60,0xC3,0x01,0x56,0xFA,0xB7,0xC8,0x0A,0x02,0x76,0x71,0x2D,0xA9,0xD8,0x09,0x4A,0x63,0x4B,
		0x76,0x6D,0x3A,0x28,0x5E,0x07,0x48,0x06,0x53,0x42,0x6D}
	mip = Mirsys(1000, 16)
	mip.IOBASE = 16
	x = Mirvar(0)
	y = Mirvar(0)
	ks = Mirvar(0)
	kG = Epoint_init()
	Bytes_to_big(len(std_priKey), std_priKey[:], ks) //ks is the standard private key
	//initiate SM2 curve
	SM2_Init()
	//generate key pair
	tmp = SM2_KeyGeneration(ks, kG)
	if tmp != 0 {
		return uint32(tmp)
	}
	Epoint_get(kG, x, y)
	Big_to_bytes(SM2_NUMWORD, x, kGxy[:], true)
	Big_to_bytes(SM2_NUMWORD, y, kGxy[SM2_NUMWORD:], true)
	if memcmp(kGxy[:], std_pubKey[:], SM2_NUMWORD*2) != 0 {
		return ERR_SELFTEST_KG
	}
	//encrypt data and compare the result with the standard data
	tmp = int(SM2_Encrypt(std_rand[:], kG, std_Message[:], len(std_Message), Cipher[:]))
	fmt.Printf("cipher1:%x\n",Cipher[:64])
	fmt.Printf("cipher2:%x\n",Cipher[64:19+64])
	fmt.Printf("cipher3:%x\n",Cipher[19+64:])
	if tmp != 0 {
		return uint32(tmp)
	}

	if memcmp(Cipher[:], std_Cipher[:], len(std_Message)+SM2_NUMWORD*3) != 0 {
		return ERR_SELFTEST_ENC
	}
	//decrypt cipher and compare the result with the standard data
	//M1 := M[:]
	tmp = int(SM2_Decrypt(ks, Cipher[:], len(std_Cipher),len(std_Message) ,M[:]))
	if tmp != 0 {
		return uint32(tmp)
	}
	if memcmp(M[:], std_Message[:], len(std_Message)) != 0 {
		return ERR_SELFTEST_DEC
	}
	fmt.Printf("message:%x\n",M)
	return 0
}
func main(){
	SM2_ENC_SelfTest()
}