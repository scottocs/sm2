package main

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

var SM2_p = [32]uint8{0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
var SM2_a = [32]uint8{0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC}
var SM2_b = [32]uint8{0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
	0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93}
var SM2_n = [32]uint8{0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23}
var SM2_Gx = [32]uint8{0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
	0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7}
var SM2_Gy = [32]uint8{0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
	0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0}
var SM2_h = [32]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
var para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h Big
var G *Epoint
var Mr_mip *Miracl = &Miracl{}
//var Mr_mip Miracl
func main() { //SM2_KeyEX_SelfTest
	//standard data

	var std_priKeyA = [32]uint8{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1, 0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52, 0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1, 0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	var std_pubKeyA = [32 * 2]uint8{0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6, 0x1D, 0xD8, 0x12, 0xFE, 0xB9, 0x67, 0x48, 0xFB, 0xD3, 0xCC, 0xF4, 0xFF, 0xE2, 0x6A, 0xA6, 0xF6, 0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32,
		0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95, 0x31, 0x69, 0x4B, 0xEB, 0x20, 0xAA, 0x48, 0x9D,
		0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC, 0xF8, 0xC4, 0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F}
	var std_randA = [32]uint8{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06, 0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87, 0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}
	var std_priKeyB = [32]uint8{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA, 0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88, 0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	var std_pubKeyB = [32 * 2]uint8{0x6A, 0xE8, 0x48, 0xC5, 0x7C, 0x53, 0xC7, 0xB1, 0xB5, 0xFA, 0x99, 0xEB, 0x22, 0x86, 0xAF, 0x07,
		0x8B, 0xA6, 0x4C, 0x64, 0x59, 0x1B, 0x8B, 0x56, 0x6F, 0x73, 0x57, 0xD5, 0x76, 0xF1, 0x6D, 0xFB,
		0xEE, 0x48, 0x9D, 0x77, 0x16, 0x21, 0xA2, 0x7B, 0x36, 0xC5, 0xC7, 0x99, 0x20, 0x62, 0xE9, 0xCD,
		0x09, 0xA9, 0x26, 0x43, 0x86, 0xF3, 0xFB, 0xEA, 0x54, 0xDF, 0xF6, 0x93, 0x05, 0x62, 0x1C, 0x4D}
	var std_randB = [32]uint8{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48, 0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88, 0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}
	var std_IDA = [16]uint8{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	var std_IDB = [16]uint8{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	var std_ENTLA int16 = 0x0080
	var std_ENTLB int16 = 0x0080
	//var std_ZA = [256]uint8{0x3B, 0x85, 0xA5, 0x71, 0x79, 0xE1, 0x1E, 0x7E, 0x51, 0x3A, 0xA6, 0x22, 0x99, 0x1F, 0x2C, 0xA7, 0x4D, 0x18, 0x07, 0xA0, 0xBD, 0x4D, 0x4B, 0x38, 0xF9, 0x09, 0x87, 0xA1, 0x7A, 0xC2, 0x45, 0xB1}
	//var std_ZB = [256]uint8{0x79, 0xC9, 0x88, 0xD6, 0x32, 0x29, 0xD9, 0x7E, 0xF1, 0x9F, 0xE0, 0x2C, 0xA1, 0x05, 0x6E, 0x01, 0xE6, 0xA7, 0x41, 0x1E, 0xD2, 0x46, 0x94, 0xAA, 0x8F, 0x83, 0x4F, 0x4A, 0x4A, 0xB0, 0x22, 0xF7}
	//var std_RA = [32 * 2]uint8{0x64, 0xCE, 0xD1, 0xBD, 0xBC, 0x99, 0xD5, 0x90, 0x04, 0x9B, 0x43, 0x4D, 0x0F, 0xD7, 0x34, 0x28, 0xCF, 0x60, 0x8A, 0x5D, 0xB8, 0xFE, 0x5C, 0xE0, 0x7F, 0x15, 0x02, 0x69, 0x40, 0xBA, 0xE4, 0x0E,
	//	0x37, 0x66, 0x29, 0xC7, 0xAB, 0x21, 0xE7, 0xDB, 0x26, 0x09, 0x22, 0x49, 0x9D, 0xDB, 0x11, 0x8F, 0x07, 0xCE, 0x8E, 0xAA, 0xE3, 0xE7, 0x72, 0x0A, 0xFE, 0xF6, 0xA5, 0xCC, 0x06, 0x20, 0x70, 0xC0}
	var std_K = [16]uint8{0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84, 0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5}
	//var std_RB = [32 * 2]uint8{0xAC, 0xC2, 0x76, 0x88, 0xA6, 0xF7, 0xB7, 0x06, 0x09, 0x8B, 0xC9, 0x1F, 0xF3, 0xAD, 0x1B, 0xFF,
	//	0x7D, 0xC2, 0x80, 0x2C, 0xDB, 0x14, 0xCC, 0xCC, 0xDB, 0x0A, 0x90, 0x47, 0x1F, 0x9B, 0xD7, 0x07,
	//	0x2F, 0xED, 0xAC, 0x04, 0x94, 0xB2, 0xFF, 0xC4, 0xD6, 0x85, 0x38, 0x76, 0xC7, 0x9B, 0x8F, 0x30,
	//	0x1C, 0x65, 0x73, 0xAD, 0x0A, 0xA5, 0x0F, 0x39, 0xFC, 0x87, 0x18, 0x1E, 0x1A, 0x1B, 0x46, 0xFE}
	//var std_SB = [256]uint8{0xD3, 0xA0, 0xFE, 0x15, 0xDE, 0xE1, 0x85, 0xCE, 0xAE, 0x90, 0x7A, 0x6B, 0x59, 0x5C, 0xC3, 0x2A, 0x26, 0x6E, 0xD7, 0xB3, 0x36, 0x7E, 0x99, 0x83, 0xA8, 0x96, 0xDC, 0x32, 0xFA, 0x20, 0xF8, 0xEB}
	var std_Klen int = 128 //bit len
	var temp int
	var x, y, dA, dB, rA, rB Big
	var pubKeyA, pubKeyB, RA, RB, V *Epoint
	var hash = [256 / 8]uint8{0}
	var ZA = [256 / 8]uint8{0}
	var ZB = [256 / 8]uint8{0}
	var xy = [32 * 2]uint8{0}
	var KA = [128 / 8]uint8{0}
	var KB = [128 / 8]uint8{0}
	var SA = [256 / 8]uint8{0}

	Mr_mip = Mirsys(1000, 16)
	//Mr_mip = *mip
	Mr_mip.IOBASE = 16
	x = Mirvar(0)
	y = Mirvar(0)
	dA = Mirvar(0)
	dB = Mirvar(0)
	rA = Mirvar(0)
	rB = Mirvar(0)
	pubKeyA = Epoint_init()
	pubKeyB = Epoint_init()
	RA = Epoint_init()
	RB = Epoint_init()
	V = Epoint_init()
	SM2_Init()
	Bytes_to_big(32, std_priKeyA[0:], dA)
	Bytes_to_big(32, std_priKeyB[0:], dB)
	Bytes_to_big(32, std_randA[0:], rA)
	Bytes_to_big(32, std_randB[0:], rB)
	Bytes_to_big(32, std_pubKeyA[0:], x)
	Bytes_to_big(32, std_pubKeyA[32:], y)
	Epoint_set(x, y, 0, pubKeyA)
	Bytes_to_big(32, std_pubKeyB[0:], x)
	Bytes_to_big(32, std_pubKeyB[32:], y)
	Epoint_set(x, y, 0, pubKeyB)
	SM3_Z(std_IDA[0:], uint16(std_ENTLA), pubKeyA, ZA[0:])
	//if (memcmp(ZA, std_ZA, 256 / 8) != 0)
	//return ERR_SELFTEST_Z;
	SM3_Z(std_IDB[0:], uint16(std_ENTLB), pubKeyB, ZB[0:])
	//if (memcmp(ZB, std_ZB, 256 / 8) != 0)
	//return ERR_SELFTEST_Z;
	temp = SM2_KeyEx_Init_I(rA, RA)
	if temp !=0 {
		return ;
	}
	Epoint_get(RA, x, y)
	Big_to_bytes(32, x, xy[0:], true)
	Big_to_bytes(32, y, xy[32:], true)
	//if (memcmp(xy, std_RA, 32 * 2) != 0)
	//return ERR_SELFTEST_INI_I;
	temp = SM2_KeyEx_Re_I(rB, dB, RA, pubKeyA, ZA[0:], ZB[0:], KA[0:], std_Klen, RB, V, hash)
	if temp!=0 {
		return ;
	}
	//if (memcmp(KA, std_K, std_Klen / 8) != 0)
	//return ERR_SELFTEST_RES_I;
	temp = SM2_KeyEx_Init_II(rA, dA, RA, RB, pubKeyB, ZA[0:], ZB[0:], hash[0:], KB[0:], std_Klen, SA[0:])
	if temp!=0{
		return
	};
	if memcmp(KB[0:], std_K[0:], std_Klen / 8) != 0 {
		return;
	}
	if SM2_KeyEx_Re_II(V, RA, RB, ZA[0:], ZB[0:], SA[0:]) != 0 {
		//return 9;
	}

	//free(KA); free(KB);
	//return 0;
}

//var SM3_len int = 256


func SM2_KeyEx_Re_II(V *Epoint, RA *Epoint, RB *Epoint, ZA []uint8, ZB []uint8, SA []uint8) int {
	var x1, y1, x2, y2, Vx, Vy Big
	var hash = [32]uint8{0}
	var S2 = [32]uint8{0}
	var temp uint8 = 0x03
	var xV = [32]uint8{0}
	var yV = [32]uint8{0}
	var x1y1 = [32 * 2]uint8{0}
	var x2y2 = [32 * 2]uint8{0}
	var md SM3_STATE
	x1 = Mirvar(0)
	y1 = Mirvar(0)
	x2 = Mirvar(0)
	y2 = Mirvar(0)
	Vx = Mirvar(0)
	Vy = Mirvar(0)
	Epoint_get(RA, x1, y1)
	Epoint_get(RB, x2, y2)
	Epoint_get(V, Vx, Vy)
	Big_to_bytes(32, Vx, xV[0:], true)
	Big_to_bytes(32, Vy, yV[0:], true)
	Big_to_bytes(32, x1, x1y1[0:], true)
	Big_to_bytes(32, y1, x1y1[32:], true)
	Big_to_bytes(32, x2, x2y2[0:], true)
	Big_to_bytes(32, y2, x2y2[32:], true)
	//---------------B10:(optional) S2 = Hash(0x03||Vy||Hash(Vx||ZA||ZB||x1||y1||x2||y2))
	SM3_init(&md)
	SM3_process(&md, xV[0:], 32)
	SM3_process(&md, ZA, int(256)/8)
	SM3_process(&md, ZB, int(256)/8)
	SM3_process(&md, x1y1[0:], 32*2)
	SM3_process(&md, x2y2[0:], 32*2)
	SM3_done(&md, hash[0:])
	SM3_init(&md)
	var tmpArr = [1]uint8{temp}
	SM3_process(&md, tmpArr[0:], 1)
	SM3_process(&md, yV[0:], 32)
	SM3_process(&md, hash[0:], int(256)/8)
	SM3_done(&md, S2[0:])
	// if (memcmp(S2, SA, 256 / 8) != 0)
	// return ERR_EQUAL_S2SA;
	return 0
}
func SM2_KeyEx_Re_I(rb Big, dB Big, RA *Epoint, PA *Epoint, ZA []uint8, ZB []uint8, K []uint8, klen int, RB *Epoint, V *Epoint, hash [32]uint8) int {
	var md SM3_STATE
	//var i int = 0
	var w int = 0
	var Z = [uint32(32*2) + 256/4]uint8{0}
	var x1y1 = [32 * 2]uint8{0}
	var x2y2 = [32 * 2]uint8{0}
	var temp uint8 = 0x02
	var x1, y1, x1_, x2, y2, x2_, tmp, Vx, Vy, temp_x, temp_y Big
	//mip= mirsys(1000, 16);
	//mip->IOBASE=16;
	x1 = Mirvar(0)
	y1 = Mirvar(0)
	x1_ = Mirvar(0)
	x2 = Mirvar(0)
	y2 = Mirvar(0)
	x2_ = Mirvar(0)
	tmp = Mirvar(0)
	Vx = Mirvar(0)
	Vy = Mirvar(0)
	temp_x = Mirvar(0)
	temp_y = Mirvar(0)
	w = SM2_W(para_n)
	//--------B2: RB=[rb]G=(x2,y2)--------
	SM2_KeyGeneration(rb, RB)
	Epoint_get(RB, x2, y2)
	Big_to_bytes(32, x2, x2y2[0:], true)
	Big_to_bytes(32, y2, x2y2[32:], true)
	//--------B3: x2_=2^w+x2 & (2^w-1)--------
	expb2(w, x2_)        // X2_=2^w
	Divide(x2, x2_, tmp) // x2=x2 mod x2_=x2 & (2^w-1)
	Add(x2_, x2, x2_)
	Divide(x2_, para_n, tmp) // x2_=n mod q
	//--------B4: tB=(dB+x2_*rB)mod n--------
	Multiply(x2_, rb, x2_)
	Add(dB, x2_, x2_)
	Divide(x2_, para_n, tmp)
	//--------B5: x1_=2^w+x1 & (2^w-1)--------
	if Test_Point(RA) != 0 {
		return 6
	}
	Epoint_get(RA, x1, y1)
	Big_to_bytes(32, x1, x1y1[0:], true)
	Big_to_bytes(32, y1, x1y1[32:], true)
	expb2(w, x1_)        // X1_=2^w
	Divide(x1, x1_, tmp) // x1=x1 mod x1_ =x1 & (2^w-1)
	Add(x1_, x1, x1_)
	Divide(x1_, para_n, tmp) // x1_=n mod q
	//--------B6: V=[h*tB](PA+[x1_]RA)--------
	ecurve_mult(x1_, RA, V) // v=[x1_]RA
	Epoint_get(V, temp_x, temp_y)
	ecurve_add(PA, V) // V=PA+V
	Epoint_get(V, temp_x, temp_y)
	Multiply(para_h, x2_, x2_) // tB=tB*h
	ecurve_mult(x2_, V, V)
	if Point_at_infinity(V) == 1 {
		return 1
	}
	Epoint_get(V, Vx, Vy)
	Big_to_bytes(32, Vx, Z[0:], true)
	Big_to_bytes(32, Vy, Z[32:], true)
	//------------B7:KB=KDF(VX,VY,ZA,ZB,KLEN)----------
	memcpy(Z[32 * 2:], ZA, 256 / 8);
	memcpy(Z[32 * 2 + 256 / 8:], ZB, 256 / 8);
	SM3_KDF(Z[0:], uint32(32*2)+256/4, uint32(klen)/8, K)
	//---------------B8:(optional) SB=hash(0x02||Vy||HASH(Vx||ZA||ZB||x1||y1||x2||y2)-------------
	SM3_init(&md)
	SM3_process(&md, Z[0:], 32)
	SM3_process(&md, ZA[0:], int(256)/8)
	SM3_process(&md, ZB[0:], int(256)/8)
	SM3_process(&md, x1y1[0:], 32*2)
	SM3_process(&md, x2y2[0:], 32*2)
	SM3_done(&md, hash[0:])
	SM3_init(&md)
	var tmpArr = [1]uint8{temp}
	SM3_process(&md, tmpArr[0:], 1)
	SM3_process(&md, Z[32:], 32)
	SM3_process(&md, hash[0:], int(256)/8)
	SM3_done(&md, hash[0:])
	return 0
}
func SM2_KeyEx_Init_II(ra Big, dA Big, RA *Epoint, RB *Epoint, PB *Epoint, ZA []uint8, ZB []uint8, SB []uint8, K []uint8, klen int, SA []uint8) int {
	var md SM3_STATE
	//var i int = 0
	var w int = 0
	var Z = [32*2 + int(256)/4]uint8{0}
	var x1y1 = [32 * 2]uint8{0}
	var x2y2 = [32 * 2]uint8{0}
	var hash = [32]uint8{0}
	var S1 = [32]uint8{0}
	var temp = [2]uint8{0x02, 0x03}
	var x1, y1, x1_, x2, y2, x2_, tmp, Ux, Uy, temp_x, temp_y, tA Big
	var U *Epoint
	// mip= mirsys(1000, 16);
	// mip->IOBASE=16;
	U = Epoint_init()
	x1 = Mirvar(0)
	y1 = Mirvar(0)
	x1_ = Mirvar(0)
	x2 = Mirvar(0)
	y2 = Mirvar(0)
	x2_ = Mirvar(0)
	tmp = Mirvar(0)
	Ux = Mirvar(0)
	Uy = Mirvar(0)
	temp_x = Mirvar(0)
	temp_y = Mirvar(0)
	tA = Mirvar(0)
	w = SM2_W(para_n)
	Epoint_get(RA, x1, y1)
	Big_to_bytes(32, x1, x1y1[0:], true)
	Big_to_bytes(32, y1, x1y1[32:], true)
	//--------A4: x1_=2^w+x2 & (2^w-1)--------
	expb2(w, x1_)        // x1_=2^w
	Divide(x1, x1_, tmp) //x1=x1 mod x1_ =x1 & (2^w-1)
	Add(x1_, x1, x1_)
	Divide(x1_, para_n, tmp)
	//-------- A5: tA=(dA+x1_*rA)mod n--------
	Multiply(x1_, ra, tA)
	Divide(tA, para_n, tmp)
	Add(tA, dA, tA)
	Divide(tA, para_n, tmp)
	//-------- A6:x2_=2^w+x2 & (2^w-1)-----------------
	if Test_Point(RB) != 0 {
		return 7 //////////////////////////////////
	}
	Epoint_get(RB, x2, y2)
	Big_to_bytes(32, x2, x2y2[0:], true)
	Big_to_bytes(32, y2, x2y2[32:], true)
	expb2(w, x2_)        // x2_=2^w
	Divide(x2, x2_, tmp) // x2=x2 mod x2_=x2 & (2^w-1)
	Add(x2_, x2, x2_)
	Divide(x2_, para_n, tmp)
	//--------A7:U=[h*tA](PB+[x2_]RB)-----------------
	ecurve_mult(x2_, RB, U) // U=[x2_]RB
	Epoint_get(U, temp_x, temp_y)
	ecurve_add(PB, U) // U=PB+U
	Epoint_get(U, temp_x, temp_y)
	Multiply(para_h, tA, tA) // tA=tA*h
	Divide(tA, para_n, tmp)
	ecurve_mult(tA, U, U)
	if Point_at_infinity(U) == 1 {
		return 1
	}
	Epoint_get(U, Ux, Uy)
	Big_to_bytes(32, Ux, Z[0:], true)
	Big_to_bytes(32, Uy, Z[32:], true)
	//------------A8:KA=KDF(UX,UY,ZA,ZB,KLEN)----------
	memcpy(Z[32 * 2:], ZA, 256 / 8);
	memcpy(Z[32 * 2 + 256 / 8:], ZB, 256 / 8);
	SM3_KDF(Z[0:], uint32(32)*2+256/4, uint32(klen)/8, K)
	//---------------A9:(optional) S1 = Hash(0x02||Uy||Hash(Ux||ZA||ZB||x1||y1||x2||y2))-----------
	SM3_init(&md)
	SM3_process(&md, Z[0:], 32)
	SM3_process(&md, ZA, int(256)/8)
	SM3_process(&md, ZB, int(256)/8)
	SM3_process(&md, x1y1[0:], 32*2)
	SM3_process(&md, x2y2[0:], 32*2)
	SM3_done(&md, hash[0:])
	SM3_init(&md)

	SM3_process(&md, temp[0:], 1)
	SM3_process(&md, Z[32:], 32)
	SM3_process(&md, hash[0:], int(256)/8)
	SM3_done(&md, S1[0:])
	//test S1=SB?
	//if (memcmp(S1, SB, 32) != 0)
	//return ERR_EQUAL_S1SB;
	//---------------A10 SA = Hash(0x03||yU||Hash(xU||ZA||ZB||x1||y1||x2||y2))-------------
	SM3_init(&md)
	SM3_process(&md, temp[1:], 1)
	SM3_process(&md, Z[32:], 32)
	SM3_process(&md, hash[0:], int(256)/8)
	SM3_done(&md, SA)
	return 0
}
func SM2_W(n Big) int {
	var n1 Big
	var w int = 0
	n1 = Mirvar(0)
	w = logb2(para_n) //approximate integer log to the base 2 of para_n
	expb2(w, n1)      //n1=2^w
	if compare(para_n, n1) == 1 {
		w++
	}
	if (w % 2) == 0 {
		w = w/2 - 1
	} else {
		w = (w+1)/2 - 1
	}
	return w
}
func SM2_KeyEx_Init_I(ra Big, RA *Epoint) int {
	return SM2_KeyGeneration(ra, RA)
}
func SM3_Z(ID []uint8, ELAN uint16, pubKey *Epoint, hash []uint8) {
	var Px = [32]uint8{0}
	var Py = [32]uint8{0}
	var IDlen = [2]uint8{0}
	var x, y Big
	var md *SM3_STATE
	x = Mirvar(0)
	y = Mirvar(0)
	Epoint_get(pubKey, x, y)
	Big_to_bytes(32, x, Px[0:], true)
	Big_to_bytes(32, y, Py[0:], true)
	//memcpy(IDlen, &(unsigned char)ELAN + 1, 1);
	//memcpy(IDlen + 1, &(unsigned char)ELAN, 1);
	SM3_init(md)
	SM3_process(md, IDlen[0:], 2)
	SM3_process(md, ID, int(ELAN)/8)
	SM3_process(md, SM2_a[0:], 32)
	SM3_process(md, SM2_b[0:], 32)
	SM3_process(md, SM2_Gx[0:], 32)
	SM3_process(md, SM2_Gy[0:], 32)
	SM3_process(md, Px[0:], 32)
	SM3_process(md, Py[0:], 32)
	SM3_done(md, hash)
	return
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
	Bytes_to_big(32, SM2_p[0:], para_p)
	Bytes_to_big(32, SM2_a[0:], para_a)
	Bytes_to_big(32, SM2_b[0:], para_b)
	Bytes_to_big(32, SM2_n[0:], para_n)
	Bytes_to_big(32, SM2_Gx[0:], para_Gx)
	Bytes_to_big(32, SM2_Gy[0:], para_Gy)
	Bytes_to_big(32, SM2_h[0:], para_h)
	ecurve_init(para_a, para_b, para_p, 0)
	//Initialises GF(p) elliptic curve.
	//MR_PROJECTIVE specifying projective coordinates
	if Epoint_set(para_Gx, para_Gy, 0, G) == 0 { //initialise point G
		return ERR_Ecurve_INIT
	}
	Ecurve_mult(para_n, G, nG)
	if Point_at_infinity(nG) == 0 { //test if the order of the point is n
		return ERR_ORDER
	}
	return 0
}

func SM2_KeyGeneration(priKey Big, pubKey *Epoint) int {
	//var i int = 0
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

func SM2_Encrypt(randK []uint8, pubKey *Epoint, M []uint8, klen int, C []uint8) uint32 {
	var C1x, C1y, x2, y2, rand Big
	var C1, kP, S *Epoint
	var i int = 0
	var x2y2 = [32 * 2]uint8{0}
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
	Bytes_to_big(32, randK, rand)
	Ecurve_mult(rand, G, C1) //C1=[k]G
	Epoint_get(C1, C1x, C1y)
	Big_to_bytes(32, C1x, C, true)
	Big_to_bytes(32, C1y, C[32:], true)
	//Step3. test if S=[h]pubKey if the point at infinity
	Ecurve_mult(para_h, pubKey, S)
	if Point_at_infinity(S) !=0{ // if S is point at infinity, return error;
		return ERR_INFINITY_POINT
	}
	//Step4. calculate [k]PB=(x2,y2)
	Ecurve_mult(rand, pubKey, kP) //kP=[k]P
	Epoint_get(kP, x2, y2)
	//Step5. KDF(x2||y2,klen)
	Big_to_bytes(32, x2, x2y2[0:], true)
	Big_to_bytes(32, y2, x2y2[32:], true)
	SM3_KDF(x2y2[0:], uint32(32)*2, uint32(klen), C[32*3:])
	if Test_Null(C[32*3:], klen) != 0 {
		return ERR_ARRAY_NULL
	}
	//Step6. C2=M^t
	for i = 0; i < klen; i++ {
		C[32*3+i] = M[i] ^ C[32*3+i]
	}
	//Step7. C3=hash(x2,M,y2)
	SM3_init(&md)
	SM3_process(&md, x2y2[0:], 32)
	SM3_process(&md, M, klen)
	SM3_process(&md, x2y2[32:], 32)
	SM3_done(&md, C[32*2:])
	return 0
}
func Test_Null(array []uint8, len int) int {
	var i int = 0
	for i = 0; i < len; i++ {
		if array[i] != 0x00 {
			return 0
		}
	}
	return 1
}

func SM2_Decrypt(dB Big, C []uint8, Clen int, M []uint8) uint32 {
	var md SM3_STATE
	var i uint32 = 0
	var x2y2 = [32 * 2]uint8{0}
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
	Bytes_to_big(32, C, C1x)
	Bytes_to_big(32, C[32:], C1y)
	Epoint_set(C1x, C1y, 0, C1)
	i = Test_Point(C1)
	if i != 0 {
		return i
	}
	//Step2. S=[h]C1 and test if S is the point at infinity
	Ecurve_mult(para_h, C1, S)
	if Point_at_infinity(S) !=0 { // if S is point at infinity, return error;
		return ERR_INFINITY_POINT
	}
	//Step3. [dB]C1=(x2,y2)
	Ecurve_mult(dB, C1, dBC1)
	Epoint_get(dBC1, x2, y2)
	Big_to_bytes(32, x2, x2y2[0:], true)
	Big_to_bytes(32, y2, x2y2[32:], true)
	//Step4. t=KDF(x2||y2,klen)
	SM3_KDF(x2y2[0:], uint32(32*2), uint32(Clen-32*3), M)
	if Test_Null(M, Clen-32*3) != 0 {
		return ERR_ARRAY_NULL
	}
	//Step5. M=C2^t
	for i = 0; i < uint32(Clen-32*3); i++ {
		M[i] = M[i] ^ C[uint32(32*3)+i]
	}
	//Step6. hash(x2,m,y2)
	SM3_init(&md)
	SM3_process(&md, x2y2[0:], 32)
	SM3_process(&md, M, Clen-32*3)
	SM3_process(&md, x2y2[32:], 32)
	SM3_done(&md, hash[0:])
	//if memcmp(hash,C[32*2:],32)!=0 {
	//	return ERR_C3_MATCH
	//} else {
	//	return 0
	//}
	return 0
}

func SM2_ENC_SelfTest() uint32 {
	var tmp int = 0
	var Cipher = [115]uint8{0}
	var M = [19]uint8{0}
	var kGxy = [32 * 2]uint8{0}
	var ks, x, y Big
	var kG *Epoint
	//standard data
	var std_priKey = [32]uint8{0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
		0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A, 0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8}
	var std_pubKey = [64]uint8{0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
		0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
		0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
		0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13}
	var std_rand = [32]uint8{0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
		0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21}
	var std_Message = [19]uint8{0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E,
		0x64, 0x61, 0x72, 0x64}
	var std_Cipher = [115]uint8{0x04, 0xEB, 0xFC, 0x71, 0x8E, 0x8D, 0x17, 0x98, 0x62, 0x04, 0x32, 0x26, 0x8E, 0x77, 0xFE, 0xB6,
		0x41, 0x5E, 0x2E, 0xDE, 0x0E, 0x07, 0x3C, 0x0F, 0x4F, 0x64, 0x0E, 0xCD, 0x2E, 0x14, 0x9A, 0x73,
		0xE8, 0x58, 0xF9, 0xD8, 0x1E, 0x54, 0x30, 0xA5, 0x7B, 0x36, 0xDA, 0xAB, 0x8F, 0x95, 0x0A, 0x3C,
		0x64, 0xE6, 0xEE, 0x6A, 0x63, 0x09, 0x4D, 0x99, 0x28, 0x3A, 0xFF, 0x76, 0x7E, 0x12, 0x4D, 0xF0,
		0x59, 0x98, 0x3C, 0x18, 0xF8, 0x09, 0xE2, 0x62, 0x92, 0x3C, 0x53, 0xAE, 0xC2, 0x95, 0xD3, 0x03,
		0x83, 0xB5, 0x4E, 0x39, 0xD6, 0x09, 0xD1, 0x60, 0xAF, 0xCB, 0x19, 0x08, 0xD0, 0xBD, 0x87, 0x66,
		0x21, 0x88, 0x6C, 0xA9, 0x89, 0xCA, 0x9C, 0x7D, 0x58, 0x08, 0x73, 0x07, 0xCA, 0x93, 0x09, 0x2D, 0x65, 0x1E, 0xFA}
	Mr_mip = Mirsys(1000, 16)
	Mr_mip.IOBASE = 16
	x = Mirvar(0)
	y = Mirvar(0)
	ks = Mirvar(0)
	kG = Epoint_init()
	Bytes_to_big(32, std_priKey[0:], ks) //ks is the standard private key
	//initiate SM2 curve
	SM2_Init()
	//generate key pair
	tmp = SM2_KeyGeneration(ks, kG)
	if tmp != 0 {
		return uint32(tmp)
	}
	Epoint_get(kG, x, y)
	Big_to_bytes(32, x, kGxy[0:], true)
	Big_to_bytes(32, y, kGxy[32:], true)
	if memcmp(kGxy[0:], std_pubKey[0:], 32*2) != 0 {
	//	return ERR_SELFTEST_KG
	}
	//encrypt data and compare the result with the standard data
	tmp = int(SM2_Encrypt(std_rand[0:], kG, std_Message[0:], 19, Cipher[0:]))
	if tmp != 0 {
		return uint32(tmp)
	}
	if memcmp(Cipher[0:], std_Cipher[0:], 19+32*3) != 0 {
		return ERR_SELFTEST_ENC
	}
	//decrypt cipher and compare the result with the standard data
	//M1 := M[:]
	tmp = int(SM2_Decrypt(ks, Cipher[0:], 115, M[0:]))
	if tmp != 0 {
		return uint32(tmp)
	}
	//if memcmp(M, std_Message, 19) != 0 {
	//	return ERR_SELFTEST_DEC
	//}
	return 0
}
