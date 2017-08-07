package main

import (
	"fmt"
	"reflect"
)
type Bigtype struct {
	len uint32
	w   []uint32
}
type Big *Bigtype

type Epoint struct {
	marker int
	X      Big
	Y      Big
	Z      Big
}

type FILE struct {
	ptr      *uint8
	cnt      int
	base     *uint8
	flag     int
	file     int
	charbuf  int
	bufsiz   int
	tmpfname *uint8
}

type small_chinese struct {
	C  *int
	V  *int
	M  *int
	NP int
}
type Miracl struct {
	base   uint32 /* number base     */
	apbase uint32 /* apparent base   */
	pack   int    /* packing density */
	lg2b   int    /* bits in base    */
	base2  uint32 /* 2^mr_lg2b          */
	user   *int   /* pointer to user supplied function */

	nib int /* length of bigs  */

	depth int     /* error tracing ..*/
	trace [24]int /* .. mechanism    */

	check  int /* overflow check  */
	fout   int /* Output to file   */
	fin    int /* Input from file  */
	active int

	infile *FILE /* Input file       */
	otfile *FILE /* Output file      */

	ira    [37]uint32 /* random number...   */
	rndptr int        /* ...array & pointer */
	borrow uint32

	/* Montgomery constants */
	ndash   uint32
	modulus Big
	pR      Big
	ACTIVE  int
	MONTY   int

	/* Elliptic Curve details   */
	SS            int /* True for Super-Singular  */
	KOBLITZ       int /* True for a Koblitz curve */
	coord         int
	Asize, Bsize  int
	M, AA, BB, CC int /* for GF(2^m) curves */

	logN                                       int /* constants for fast fourier fft multiplication */
	nprimes, degree                            int
	prime, cr                                  *int
	inverse                                    *int
	roots                                      **int
	chin                                       small_chinese
	const1, const2, const3                     int
	msw, lsw                                   uint32
	s1, s2, t                                  **int
	wa, wb, wc                                 *int
	same, first_one, debug                     int
	w0, w1, w2, w3, w4, w5, w6, w7, w8         Big
	w9, w10, w11, w12, w13, w14, w15, sru, one Big
	A, B                                       Big

	/* User modifiables */
	IOBSIZ int /* size of i/o buffer */
	ERCON  int /* error control   */
	ERNUM  int /* last error code */
	NTRY   int /* no. of tries for probablistic primality testing   */
	INPLEN int /* input length               */
	IOBASE int /* base for input and output */

	EXACT  int    /* exact flag      */
	RPOINT int    /* =ON for radix point, =OFF for fractions in output */
	TRACER int    /* turns trace tracker on/off */
	PRIMES *int   /* small primes array         */
	IOBUFF *uint8 /* i/o buffer    */

	workprec, stprec, RS, RD                int
	D, db, n, p                             float32 //c is double
	a, b, c, d, r, q, oldn, ndig            int
	u, v, ku, kv                            uint32
	last, carryon                           int
	pi                                      Big
	workspace                               *uint8
	TWIST, qnr, cnr, pmod8, pmod9, NO_CARRY int
}
var Mr_mip *Miracl = &Miracl{}

func memcpy ( buf1 []uint8, buf2 []uint8,count int) {

	if count == 0{
		return
	}
	var i int =0
	for i < count  {
		buf1[i]=buf2[i]
		i++
	}
}

func memcmp ( buf1 []uint8, buf2 []uint8,count int) int {

	if count == 0{
		return 0
	}
	var i int =0

	for buf1[i] == buf2[i]  {
		if i == count-1{
			break
		}
		i ++
	}
	return int(buf1[i] - buf2[i])
}
func compare(x, y Big) int {
	var m, n, sig int
	var sx, sy uint32
	if x == y {
		return 0
	}
	sx = x.len & (1 << 31)
	sy = y.len & (1 << 31)
	if sx == 0 {
		sig = 1
	} else {
		sig = -1
	}
	if sx != sy {
		return sig
	}
	m = int(x.len & (1<<31 - 1))
	n = int(y.len & (1<<31 - 1))
	if m > n {
		return sig
	}
	if m < n {
		return -sig
	}
	for m > 0 {
		m--
		if x.w[m] > y.w[m] {
			return sig
		} //大于号小于号未实现
		if x.w[m] < y.w[m] {
			return -sig
		}
	}
	return 0
}

func prepare_monty(n Big) uint32 { /* prepare Montgomery modulus */

	if Mr_mip.ERNUM != 0 {
		return uint32(0)
	}
	/* Is it set-up already? */
	if size(Mr_mip.modulus) != 0 {
		if mr_compare(n, Mr_mip.modulus) == 0 {
			return Mr_mip.ndash
		}
	}
	MR_IN(80)

	if size(n) <= 2 {
		mr_berror(19)
		Mr_mip.depth--
		return uint32(0)
	}
	zero(Mr_mip.w6)
	zero(Mr_mip.w15)
	/* set a small negative QNR (on the assumption that n is prime!) */
	/* These defaults can be over-ridden                             */

	/* Did you know that for p=2 mod 3, -3 is a QNR? */

	Mr_mip.pmod8 = remain(n, 8)

	switch Mr_mip.pmod8 {
	case 0:
	case 1:
	case 2:
	case 4:
	case 6:
		Mr_mip.qnr = 0 /* none defined */
		break
	case 3:
		Mr_mip.qnr = -1
		break
	case 5:
		Mr_mip.qnr = -2
		break
	case 7:
		Mr_mip.qnr = -1
		break
	}
	Mr_mip.pmod9 = remain(n, 9)
	Mr_mip.NO_CARRY = 0
	if n.w[n.len-1]>>28 < 5 {
		Mr_mip.NO_CARRY = 1
	}
	Mr_mip.MONTY = 1
	convert(1, Mr_mip.one)
	if Mr_mip.MONTY == 0 { /* Montgomery arithmetic is turned off */
		copy(n, Mr_mip.modulus)
		Mr_mip.ndash = 0
		Mr_mip.depth--
		return uint32(0)
	}
	Mr_mip.w6.len = 2
	Mr_mip.w6.w = make([]uint32,2,2)
	Mr_mip.w6.w[0] = 0
	Mr_mip.w6.w[1] = 1 /* w6 = base */
	Mr_mip.w15.len = 1
	Mr_mip.w15.w = make([]uint32,1,1)
	Mr_mip.w15.w[0] = n.w[0]                             /* w15 = n mod base */
	if invmodp(Mr_mip.w15, Mr_mip.w6, Mr_mip.w14) != 1 { /* problems */
		mr_berror(19)
		Mr_mip.depth--

		return uint32(0)
	}
	Mr_mip.ndash = Mr_mip.base - Mr_mip.w14.w[0] /* = N' mod b */
	copy(n, Mr_mip.modulus)
	Mr_mip.check = 0
	mr_shift(Mr_mip.modulus, int(Mr_mip.modulus.len), Mr_mip.pR)
	Mr_mip.check = 1
	nres(Mr_mip.one, Mr_mip.one)
	Mr_mip.depth--
	return Mr_mip.ndash
}

func ecurve_init(a Big, b Big, p Big, type1 int) { /* Initialize the active ecurve    *
	 * Asize indicate size of A        *
	 * Bsize indicate size of B        */
	var as int
	if Mr_mip.ERNUM != 0 {
		return
	}
	Mr_mip.SS = 0 /* no special support for super-singular curves */
	prepare_monty(p)
	Mr_mip.Asize = size(a)
	if mr_abs(Mr_mip.Asize) == 1<<30 {
		if Mr_mip.Asize >= 0 { /* big positive number - check it isn't minus something small */
			copy(a, Mr_mip.w1)
			Divide(Mr_mip.w1, p, p)
			subtract(p, Mr_mip.w1, Mr_mip.w1)
			as = size(Mr_mip.w1)
			if as < 1<<30 {
				Mr_mip.Asize = -as
			}
		}
	}
	nres(a, Mr_mip.A)
	Mr_mip.Bsize = size(b)
	if mr_abs(Mr_mip.Bsize) == 1<<30 {
		if Mr_mip.Bsize >= 0 { /* big positive number - check it isn't minus something small */
			copy(b, Mr_mip.w1)
			Divide(Mr_mip.w1, p, p)
			subtract(p, Mr_mip.w1, Mr_mip.w1)
			as = size(Mr_mip.w1)
			if as < 1<<30 {
				Mr_mip.Bsize = -as
			}
		}
	}
	nres(b, Mr_mip.B)
	if type1 == 2 {
		Mr_mip.coord = 0
	} else {
		Mr_mip.coord = type1
	}
	Mr_mip.depth--
	return
}
func Ecurve_mult(e Big, pa *Epoint, pt *Epoint) int { /* pt=e*pa; */
	var i, j, n, nb, nbs, nzs, nadds int
	var table [8]*Epoint
	var work [8]Big
	var mem *uint8
	var mem1 *uint8
	var p *Epoint
	var ce, ch int
	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(95)
	if size(e) == 0 { /* multiplied by 0 */
		Epoint_set(nil, nil, 0, pt)
		Mr_mip.depth--
		return 0
	}
	copy(e, Mr_mip.w9)
	/*    epoint_norm(pa); */
	epoint_copy(pa, pt)

	if size(Mr_mip.w9) < 0 { /* pt = -pt */
		negify(Mr_mip.w9, Mr_mip.w9)
		epoint_negate(pt)
	}

	if size(Mr_mip.w9) == 1 {
		Mr_mip.depth--
		return 0
	}

	premult(Mr_mip.w9, 3, Mr_mip.w10) /* h=3*e */

	if Mr_mip.base == Mr_mip.base2 {

		//mem = *uint8(ecp_memalloc(8))
		//
		//mem1 = *uint8(memalloc(8))

		for i = 0; i <= 7; i++ {
			table[i] = epoint_init_mem(mem, i)
			work[i] = mirvar_mem(mem1, i)
		}

		epoint_copy(pt, table[0])
		epoint_copy(table[0], table[7])
		ecurve_double(table[7])
		/*   epoint_norm(table[MR_ECC_STORE_N-1]); */

		for i = 1; i < 7; i++ { /* precomputation */
			epoint_copy(table[i-1], table[i])
			ecurve_add(table[7], table[i])
		}
		ecurve_add(table[6], table[7])

		epoint_multi_norm(8, work[0:], table[0:])

		nb = logb2(Mr_mip.w10)
		nadds = 0
		Epoint_set(nil, nil, 0, pt)
		for i = nb - 1; i >= 1; { /* add/subtract */
			//if Mr_mip.user != nil {
			//	*Mr_mip.user()
			//}
			n = mr_naf_window(Mr_mip.w9, Mr_mip.w10, i, &nbs, &nzs, 8)
			for j = 0; j < nbs; j++ {
				ecurve_double(pt)
			}
			if n > 0 {
				ecurve_add(table[n/2], pt)
				nadds++
			}
			if n < 0 {
				ecurve_sub(table[(-n)/2], pt)
				nadds++
			}
			i -= nbs
			if nzs != 0 {
				for j = 0; j < nzs; j++ {
					ecurve_double(pt)
				}
				i -= nzs
			}
		}

		ecp_memkill(mem, 8)

		memkill(mem1, 8)

	} else {
		//mem = *uint8(ecp_memalloc(1))
		p = epoint_init_mem(mem, 0)
		epoint_norm(pt)
		epoint_copy(pt, p)

		nadds = 0
		expb2(logb2(Mr_mip.w10)-1, Mr_mip.w11)
		mr_psub(Mr_mip.w10, Mr_mip.w11, Mr_mip.w10)
		subdiv(Mr_mip.w11, 2, Mr_mip.w11)
		for size(Mr_mip.w11) > 1 { /* add/subtract method */
			//if Mr_mip.user != nil {
			//	*Mr_mip.user()
			//}

			ecurve_double(pt)
			ce = mr_compare(Mr_mip.w9, Mr_mip.w11)  /* e(i)=1? */
			ch = mr_compare(Mr_mip.w10, Mr_mip.w11) /* h(i)=1? */
			if ch >= 0 {                            /* h(i)=1 */
				if ce < 0 {
					ecurve_add(p, pt)
					nadds++
				}
				mr_psub(Mr_mip.w10, Mr_mip.w11, Mr_mip.w10)
			}
			if ce >= 0 { /* e(i)=1 */
				if ch < 0 {
					ecurve_sub(p, pt)
					nadds++
				}
				mr_psub(Mr_mip.w9, Mr_mip.w11, Mr_mip.w9)
			}
			subdiv(Mr_mip.w11, 2, Mr_mip.w11)
		}
		ecp_memkill(mem, 1)
	}

	Mr_mip.depth--
	return nadds
}

func Test_Point(point *Epoint) uint32 {
	var x, y, x_3, tmp Big
	x = Mirvar(0)
	y = Mirvar(0)
	x_3 = Mirvar(0)
	tmp = Mirvar(0)
	//test if y^2=x^3+ax+b
	Epoint_get(point, x, y)
	Power(x, 3, para_p, x_3) //x_3=x^3 mod p
	Multiply(x, para_a, x)   //x=a*x
	Divide(x, para_p, tmp)   //x=a*x mod p , tmp=a*x/p
	Add(x_3, x, x)           //x=x^3+ax
	Add(x, para_b, x)        //x=x^3+ax+b
	Divide(x, para_p, tmp)   //x=x^3+ax+b mod p
	Power(y, 2, para_p, y)   //y=y^2 mod p
	if compare(x, y) != 0 {
		return ERR_NOT_VALID_POINT
	} else {
		return 0
	}
}

func Test_PubKey(pubKey *Epoint) uint32 {
	var x, y Big
	var nP *Epoint
	x = Mirvar(0)
	y = Mirvar(0)
	//x_3 = Mirvar(0)
	//tmp = Mirvar(0)
	nP = Epoint_init()
	//test if the pubKey is the point at infinity
	if Point_at_infinity(pubKey) != 0 { // if pubKey is point at infinity, return error;
		return ERR_INFINITY_POINT
	}
	//test if x<p and y<p both hold
	Epoint_get(pubKey, x, y)
	if (compare(x, para_p) != -1) || (compare(y, para_p) != -1) {
		return ERR_NOT_VALID_ELEMENT
	}
	if Test_Point(pubKey) != 0 {
		return ERR_NOT_VALID_POINT
	}
	//test if the order of pubKey is equal to n
	Ecurve_mult(para_n, pubKey, nP) // nP=[n]P
	if Point_at_infinity(nP) == 0 { // if np is point NOT at infinity, return error;
		return ERR_ORDER
	}
	return 0
}

//import (
//	"text/template/parse"
//	"math"
//)
//muldiv等一些函数在c源代码中其实并未定义，使用ifdef函数将其注释掉，因此我也不知道该怎么办


func mirvar_mem_variable(mem *uint8, index int, sz int) Big {
	var x Big = Mirvar(0)
	//var align, offset, r int
	//var ptr *uint8
	///* alignment */
	//offset = 0
	//r = (unsigned long)mem % sizeof(long)
	//if r > 0 {
	//	offset = sizeof(long) - r
	//}
	//
	//x = Big(&mem[offset+mr_size(sz)*index])
	////#define mr_esize(n) (((sizeof(epoint)+mr_big_reserve(3,(n)))-1)/MR_SL+1)*MR_SL
	////#define mr_big_reserve(n,m) ((n)*mr_size(m)+MR_SL)
	////#define mr_size(n) (((sizeof(struct bigtype)+((n)+2)*sizeof(mr_utype))-1)/MR_SL+1)*MR_SL
	////#define mr_utype int
	////#define MR_SL sizeof(long)
	//ptr = *uint8(&x.w)
	//align = (unsigned long)(ptr + sizeof(*uint32)) % sizeof(mr_small)
	//x.w = (*uint32)(ptr + sizeof(*uint32) + sizeof(uint32) - align)

	return x
}

func mirvar_mem(mem *uint8, index int) Big { /* initialize big/flash number from pre-allocated memory */
	if Mr_mip.ERNUM != 0 {
		return nil
	}
	return mirvar_mem_variable(mem, index, Mr_mip.nib-1)
}

func Epoint_init() *Epoint { /* initialise epoint to general point at infinity. */
	var p = &Epoint{2, nil, nil, nil}
	//var ptr *uint8
	//
	//if Mr_mip.ERNUM {
	//	return nil
	//}
	//
	//MR_IN(96)
	//
	///* Create space for whole structure in one heap access */
	//
	//p = *Epoint(mr_alloc(mr_esize(Mr_mip.nib-1), 1)) //不会改
	////#define mr_esize(n) (((sizeof(epoint)+mr_big_reserve(3,(n)))-1)/MR_SL+1)*MR_SL
	////#define mr_big_reserve(n,m) ((n)*mr_size(m)+MR_SL)
	////#define mr_size(n) (((sizeof(struct bigtype)+((n)+2)*sizeof(mr_utype))-1)/MR_SL+1)*MR_SL
	////#define mr_utype int
	////#define MR_SL sizeof(long)
	//ptr = (*uint8)p + sizeof(Epoint)
	//p.X = mirvar_mem(ptr, 0)
	//p.Y = mirvar_mem(ptr, 1)
	//p.Z = mirvar_mem(ptr, 2)
	p.X = Mirvar(0)
	p.Y = Mirvar(0)
	p.Z = Mirvar(0)
	p.marker = 2
	Mr_mip.depth--
	return p
}

func Point_at_infinity(p *Epoint) int {
	if p == nil {
		return 0
	}
	if p.marker == 2 {
		return 1
	}
	return 0
}

func Big_to_bytes(max int, x Big, ptr []uint8, justify bool) int { /* convert positive big into octet string */
	var i, j, r, m, n, len, start int
	var dig, wrd uint32
	var ch uint16

	if Mr_mip.ERNUM != 0 || max < 0 {
		return 0
	}

	if max == 0 && justify {
		return 0
	}
	if size(x) == 0 {
		if justify {
			for i = 0; i < max; i++ {
				ptr[i] = 0
			}
			return max
		}
		return 0
	}

	MR_IN(141)

	mr_lzero(x) /* should not be needed.... */

	if Mr_mip.base == 0 {
		m = 32 / 8
		n = int(x.len & (1<<31 - 1))
		n--
		len = n * m
		wrd = x.w[n] /* most significant */
		r = 0
		for wrd != uint32(0) {
			r++
			wrd >>= 8
			len++
		}
		r %= m

		if max > 0 && len > max {
			mr_berror(14)
			Mr_mip.depth--
			return 0
		}

		if justify {
			start = max - len
			for i = 0; i < start; i++ {
				ptr[i] = 0
			}
		} else {
			start = 0
		}

		if r != 0 {
			wrd = x.w[n]
			n--
			for i = r - 1; i >= 0; i-- {
				ptr[start+i] = uint8(wrd & 0xFF)
				wrd >>= 8
			}
		}

		for i = r; i < len; i += m {
			wrd = x.w[n]
			n--
			for j = m - 1; j >= 0; j-- {
				ptr[start+i+j] = uint8(wrd & 0xFF)
				wrd >>= 8
			}
		}

	} else {
		copy(x, Mr_mip.w1)
		for len = 0; ; len++ {
			if Mr_mip.ERNUM != 0 {
				break
			}

			if size(Mr_mip.w1) == 0 {
				if justify {
					if len == max {
						break
					}
				} else {
					break
				}
			}
			if max > 0 && len >= max {
				mr_berror(14)
				Mr_mip.depth--
				return 0
			}
			dig = uint32(subdiv(Mr_mip.w1, 256, Mr_mip.w1))
			ch = uint16(dig)

			for i = len; i > 0; i-- {
				ptr[i] = ptr[i-1]
			}
			ptr[0] = uint8(ch)
		}
	}

	Mr_mip.depth--
	if justify {
		return max
	} else {
		return len
	}
}

func Bytes_to_big(len int, ptr []uint8, x Big) { /* convert len bytes into a big           *
	* The first byte is the Most significant */
	var cur int
	var i, j, m, n, r int
	var dig, wrd uint32
	var ch uint16

	if Mr_mip.ERNUM != 0 {
		return
	}
	MR_IN(140)

	zero(x)
	//fmt.Println(n,m,i,x)
	if len <= 0 {
		Mr_mip.depth--
		return
	}
	/* remove leading zeros.. */

	for ptr[cur] == 0 {
		cur++
		len--
		if len == 0 {
			Mr_mip.depth--
			return
		}
	}
	if Mr_mip.base == 0 { /* pack bytes directly into big */
		m = 32 / 8
		n = len / m
		r = len % m
		wrd = uint32(0)
		if r != 0 {
			n++
			for j = 0; j < r; j++ {
				wrd <<= 8
				wrd |= uint32(ptr[cur]) //源代码中uint16为unsigned char
				cur++
			}
		}
		x.len = uint32(n)
		x.w = make([]uint32, n)
		if n > Mr_mip.nib && Mr_mip.check != 0 {
			mr_berror(3)
			Mr_mip.depth--
			return
		}
		if r != 0 {
			n--
			x.w[n] = wrd
		}
		for i = n - 1; i >= 0; i-- {
			for j = 0; j < m; j++ {
				wrd <<= 8
				wrd |= uint32(ptr[cur])
				cur++
			}
			//fmt.Println(n,m,i,x)
			x.w[i] = wrd
		}
		mr_lzero(x) /* needed */
	} else {
		for i = 0; i < len; i++ {
			if Mr_mip.ERNUM != 0 {
				break
			}
			premult(x, 256, x)

			ch = uint16(ptr[i])
			dig = uint32(ch)
			incr(x, int(dig), x)
		}
	}
	Mr_mip.depth--
}

func Power(x Big, n uint32, z Big, w Big) { /* raise big number to int power  w=x^n *
	* (mod z if z and w distinct)          */
	var norm uint32
	copy(x, Mr_mip.w5)
	zero(w)
	if (Mr_mip.ERNUM != 0) || size(Mr_mip.w5) == 0 {
		return
	}
	convert(1, w)
	if n == 0 {
		return
	}

	MR_IN(17)

	if n < 0 {
		mr_berror(10)
		Mr_mip.depth--
		return
	}

	if w == z {
		for true { /* "Russian peasant" exponentiation */
			if n%2 != 0 {
				Multiply(w, Mr_mip.w5, w)
			}
			n /= 2
			if Mr_mip.ERNUM != 0 || n == 0 {
				break
			}
			Multiply(Mr_mip.w5, Mr_mip.w5, Mr_mip.w5)
		}
	} else {
		norm = normalise(z, z)
		Divide(Mr_mip.w5, z, z)
		for true {
			//if Mr_mip.user != nil {
			//	*Mr_mip.user()
			//}

			if n%2 != 0 {
				mad(w, Mr_mip.w5, Mr_mip.w5, z, z, w)
			}
			n /= 2
			if Mr_mip.ERNUM != 0 || n == 0 {
				break
			}
			mad(Mr_mip.w5, Mr_mip.w5, Mr_mip.w5, z, z, Mr_mip.w5)
		}
		if norm != 1 {
			mr_sdiv(z, norm, z)
			Divide(w, z, z)
		}
	}
	Mr_mip.depth--
}

/*func mr_track(){
var i int
for i=0;i<Mr_mip.depth;i++ {
	fputc('-', stdout)
}
fputc('>',stdout)
mputs(names[Mr_mip.trace[Mr_mip.depth]])
fputc('\n',stdout)
}*/

//mr_alloc函数，因void尚未实现
//func mr_alloc(num,size int)*void {
//	var p *uint8
//
//	//if Mr_mip == nil {
//	//	p = *uint8(calloc(num, size)) //calloc好像是stalib的函数
//	//	return *void(p)
//	//}
//	//
//	//if Mr_mip.ERNUM {
//	//	return nil
//	//}
//	//
//	//p = *void(calloc(num, size))
//	//if p == nil {
//	//	mr_berror(8)
//	//}
//	return *void(p)
//}

func MR_IN(n int) {
	Mr_mip.depth++
	if Mr_mip.depth < 24 {
		Mr_mip.trace[Mr_mip.depth] = n
		if Mr_mip.TRACER != 0 {
			//mr_track()这个函数未实现
		}
	}
}

func Mirvar(iv int) Big { //未实现
	var x Big
	//var align int
	//var ptr uint8

	if Mr_mip.ERNUM != 0 {
		return nil
	}
	MR_IN(23)

	//错误声明函数？未实现
	//	if Mr_mip.active != 0 {
	//		mr_berror(MR_ERR_NO_MIRSYS)
	//	MR_OUT
	//	return NULL
	//}
	/*x=(Big)mr_alloc(mr_size( Mr_mip.nib-1),1)
	if x==nil {          //因为null和big的转换未实现
		Mr_mip.depth--
		return x
	}

	ptr=(*uint8)&x.w
	align=(unsigned long)(ptr+sizeof(var uint32 *))%sizeof(var uint32)

	x.w=(var uint32 *)(ptr+sizeof(var uint32 *)+sizeof(var uint32)-align)

	if (iv!=0) convert(iv,x)
	MR_OUT*/
	x = &Bigtype{0, nil} // has type *Vertex
	return x
}

func mr_lent(x Big) int {
	var lx uint32
	// MR_IBITS 32
	//#define MR_MSBIT ((unsigned int)1<<(MR_IBITS-1))
	//#define MR_OBITS (MR_MSBIT-1)
	//lx=(x->len&(MR_OBITS));
	var mr_msbit uint32 = (uint32(1)<<31)
	lx = x.len & (mr_msbit - 1)
	return int((lx & (0xffff)) + ((lx >> (16)) & (0xffff)))
}


func zero(x Big) { /* set big/flash number to zero */
	var i,n int
	var g []uint32
	if x==nil {
		return
	}
	n=mr_lent(x)
	n=int(x.len)
	g=x.w
	for i=0;i<n;i++ {
		g[i] = 0 //此处未决
	}
	x.len=0
}
func mr_lzero(x Big) { /*  strip leading zeros from big number  */
	var s uint32
	var m int
	s = x.len & (1 << 31)
	m = int(x.len & ((1 << 31) - 1))
	for m > 0 && (x.w[m-1] == 0) {
		m--
	}
	x.len = uint32(m)
	if m > 0 {
		x.len |= s
	}
}

func mr_compare(x, y Big) int {
	var m, n, sig int
	var sx, sy uint32
	if x == y {
		return 0
	}
	sx = x.len & (1 << 31)
	sy = y.len & (1 << 31)
	if sx == 0 {
		sig = 1
	} else {
		sig = -1
	}
	if sx != sy {
		return sig
	}
	m = int(x.len & (1<<31 - 1))
	n = int(y.len & (1<<31 - 1))
	if m > n {
		return sig
	}
	if m < n {
		return -sig
	}
	for m > 0 {
		m--
		if x.w[m] > y.w[m] {
			return sig
		} //大于号小于号未实现
		if x.w[m] < y.w[m] {
			return -sig
		}
	}
	return 0
}

func mr_psub(x, y, z Big) { /*  subtract two Big numbers z=x-y      *
	*  where x and y are positive and x>y  */
	var i, lx, ly int
	var borrow, pdiff uint32
	//var gx, gy, gz []uint32

	lx = int(x.len)
	ly = int(y.len)
	if ly > lx {
		//mr_berror(4)
		return
	}
	if y != z {
		copy(x, z)
	} else {
		ly = lx
	}
	z.len = uint32(lx)
	//y.w = make([]uint32,ly,ly)
	//z.w = make([]uint32,z.len,z.len)
	//gx = x.w
	//gy = y.w
	//gz = z.w
	borrow = 0

	if Mr_mip.base == 0 {
		for i = 0; i < ly || borrow > 0; i++ { /* subtract by columns */

			if i > lx {
				//mr_berror(MR_ERR_NEG_RESULT);
				return
			}
			if i>=ly{
				y.w = append(y.w,make([]uint32,lx - len(y.w))...)
			}
			if i >= len(y.w){
				y.w= append(y.w,make([]uint32,i-len(y.w)+1)...)
			}
			pdiff = x.w[i] - y.w[i] - borrow
			if pdiff < x.w[i] {
				borrow = 0
			} else if pdiff > x.w[i] {
				borrow = 1
			}
			z.w[i] = pdiff
		}
	} else {
		for i = 0; i < ly || borrow > 0; i++ { /* subtract by columns */
			if i > lx {
				//mr_berror(MR_ERR_NEG_RESULT)
				return
			}
			if i>=ly{
				y.w = append(y.w,make([]uint32,lx - len(y.w))...)
			}
			pdiff = y.w[i] + borrow
			borrow = 0
			if x.w[i] >= pdiff {
				pdiff = x.w[i] - pdiff
			} else { /* set borrow */
				pdiff = Mr_mip.base + x.w[i] - pdiff
				borrow = 1
			}
			z.w[i] = pdiff
		}
	}
	mr_lzero(z)
}
func mr_sdiv(x Big, sn uint32, z Big) uint32 {
	var i, xl int
	var sr uint32
	//var xg,zg []uint32
	sr = 0
	xl = int(x.len & (1<<31 - 1))
	if x != z {
		zero(z)
	}
	if Mr_mip.base == 0 {
		//xg = x.w
		//zg = z.w
		for i = xl - 1; i >= 0; i-- {
			z.w[i] = muldvm(sr, x.w[i], sn, &sr) //很奇怪，找不到定义
		}
	} else {
		for i = xl - 1; i >= 0; i-- {
			z.w[i] = muldiv(sr, Mr_mip.base, x.w[i], sn, &sr)
		}
	}
	z.len = x.len
	mr_lzero(z)
	return sr
}
func mr_pmul(x Big, sn uint32, z Big) {
	var m, xl int
	var sx, carry uint32
	//var xg, zg []uint32
	if x != z {
		zero(z)
		if sn == 0 {
			return
		}
	} else if sn == 0 {
		zero(z)
		return
	}
	m = 0
	carry = 0
	sx = x.len & (1 << 31)
	xl = int(x.len & (1<<31 - 1))
	if Mr_mip.base == 0 {
		//xg = x.w
		//zg = z.w
		z.w = append(z.w, make([]uint32,xl-int(z.len))...)
		for m = 0; m < xl; m++ {
			//if z.len < uint32(xl) {
			//	z.w = append(z.w, 0)
			//}
			carry = muldvd(x.w[m], sn, carry, &z.w[m])
		}
		if carry > 0 {
			m = xl
			if m >= Mr_mip.nib {
				if Mr_mip.check != 0 {
					//mr_berror(3)
					return
				}
			}
			if m > len(z.w)-1{
				z.w = append(z.w, make([]uint32,m+1 - len(z.w))...)
			}
			z.w[m] = carry
			z.len = uint32(m + 1)
		} else {
			z.len = uint32(xl)
		}
	} else {
		for m < xl || carry > 0 {
			if m > Mr_mip.nib {
				if Mr_mip.check != 0 {
					//mr_berror(MR_ERR_OVERFLOW)
					return
				}
			}
		}
		//carry=muldiv(x.w[m],sn,carry,Mr_mip.base,&z.w[m]);
		m++
		z.len = uint32(m)
	}
	if z.len != 0 {
		z.len |= sx
	}
}
func normalise(x, y Big) uint32 { /* normalise divisor */
	var norm, r uint32
	var len int
	MR_IN(4)

	if x != y {
		copy(x, y)
	}
	len = int(y.len & (1<<31 - 1))
	if Mr_mip.base == 0 {
		r = y.w[len-1] + 1
		if r == 0 {
			norm = 1
		} else { /*norm=muldvm(uint32(1),uint32(0),r,&r)*/
			norm=muldvm(uint32(1),uint32(0),r,&r);
		}
		if norm != 1 {
			mr_pmul(y, norm, y)
		}
	} else {
		norm = Mr_mip.base / (uint32(y.w[len-1] + 1))
		if norm != 1 {
			mr_pmul(y, norm, y)
		}
	}
	Mr_mip.depth--
	return norm
}

func Divide(x, y, z Big) {
	var carry, attemp, ldy, sdy, ra, r, d, tst, psum uint32
	var sx, sy, sz, borrow, dig uint32
	//var yg []uint32
	var i, k, m, x0, y0, w00, check int
	var w0 Big
	if Mr_mip.ERNUM != 0 {
		return
	}
	w0 =Mr_mip.w0

	MR_IN(6)
	if x == y { //都是错误声明
		mr_berror(7)
	}
	if mr_notint(x) || mr_notint(y) {
		mr_berror(12)
	}
	if y.len == 0 {
		mr_berror(2)
	}
	if Mr_mip.ERNUM != 0 {
		Mr_mip.depth--
		return
	}
	sx = x.len & (1 << 31)
	sy = y.len & (1 << 31)
	sz = sx ^ sy
	x.len &= (1 << 31) - 1
	y.len &= (1 << 31) - 1
	x0 = int(x.len)
	y0 = int(y.len)
	copy(x, w0)
	w00 = int(w0.len)
	if Mr_mip.check != 0 {
		if w00-y0+1 > Mr_mip.nib {
			mr_berror(3)
			Mr_mip.depth--
			return
		}
	}
	d = 0
	if x0 == y0 {
		if x0 == 1 {
			d = w0.w[0] / y.w[0]       //除法未实现
			w0.w[0] = w0.w[0] % y.w[0] //取模未实现
			mr_lzero(w0)
		} else if (w0.w[x0-1] / 4) < y.w[x0-1] {
			for mr_compare(w0, y) >= 0 { /* mr_small quotient - so do up to four subtracts instead */
				mr_psub(w0, y, w0)
				d++
			}
		}
	}
	if mr_compare(w0, y) < 0 { /*  x less than y - so x becomes remainder */
		if x != z /* testing parameters */ {
			copy(w0, x)
			if x.len != 0 {
				x.len |= sx
			}
		}
		if y != z {
			zero(z)
			//z.w[0] = uint32(d)
			if d > 0 {
				*z = Bigtype{sz | 1,make([]uint32,sz | 1)}
				z.w[0] = uint32(d)
			}
		}
		y.len |= sy
		Mr_mip.depth--
		return
	}
	if y0 == 1 {
		r = mr_sdiv(w0, uint32(y.w[0]), w0)
		if y != z {
			copy(w0, z)
			z.len |= sz
		}
		if x != z {
			zero(x)
			x.w[0] = uint32(r)
			if r > 0 {
				x.len = sx | 1
			}
		}
		y.len |= sy
		Mr_mip.depth--
		return
	}
	if y != z {
		zero(z)
	}
	d = normalise(y, y)
	check = Mr_mip.check
	Mr_mip.check = 0

	if Mr_mip.base == 0 {
		if d != 1 {
			mr_pmul(w0, d, w0)
		}
		ldy = y.w[y0-1]
		sdy = y.w[y0-2]
		//w0g = w0.w
		//yg = y.w
		for k = w00 - 1; k >= y0-1; k-- {
			carry = 0
			if len(w0.w) < k+2{
				w0.w = append(w0.w, make([]uint32,k+2 - len(w0.w))...)
			}

			if w0.w[k+1] == ldy /* guess next quotient digit */ {
				attemp = 1 << 32 - 1
				ra = ldy + w0.w[k]
				if ra < ldy {
					carry = 1
				}
			} else {
				attemp=muldvm(w0.w[k+1],w0.w[k],ldy,&ra)
			}
			for carry == 0 {
				tst = muldvd(sdy, attemp, uint32(0), &r)

				if tst < ra || (tst == ra && r <= w0.w[k-1]) {
					break
				}
				attemp-- /* refine guess */
				ra += ldy
				if ra < ldy {
					carry = 1
				}
			}
			m = k - y0 + 1
			if attemp > 0 {
				borrow = 0
				for i = 0; i < y0; i++ {
					borrow = uint32(muldvd(attemp, y.w[i], borrow, &dig))
					if w0.w[m+i] < dig {
						borrow++
					}
					w0.w[m+i] -= dig
					w0.w[m+i] += 0
				}
				if w0.w[k+1] < borrow { /* whoops! - over did it */
					w0.w[k+1] = 0
					carry = 0
					for i = 0; i < y0; i++ { /* compensate for error ... */
						psum = w0.w[m+i] + y.w[i] + carry
						if psum > y.w[i] {
							carry = 0
						}
						if psum < y.w[i] {
							carry = 1
						}
						w0.w[m+i] = psum
					}
					attemp-- /* ... and adjust guess */
				} else {
					w0.w[k+1] -= borrow
				}
			}
			if k == w00-1 && attemp == 0 {
				w00--
			} else if y != z {
				if m+1 > len(z.w){
					z.w = append(z.w, make([]uint32,m+1-len(z.w))...)
				}
				z.w[m] = attemp
			}
		}
	} else {
		if d != 1 {
			mr_pmul(w0, d, w0)
		}
		ldy = y.w[y0-1]
		sdy = y.w[y0-2]

		for k = w00 - 1; k >= y0-1; k-- { /* long division */
			if w0.w[k+1] == ldy /* guess next quotient digit */ {
				attemp = Mr_mip.base - 1
				ra = ldy + w0.w[k]
			} else {
				attemp = muldiv(w0.w[k+1], Mr_mip.base, w0.w[k], ldy, &ra)
			}
		}
		for ra < Mr_mip.base {
			tst = muldiv(sdy, attemp, uint32(0), Mr_mip.base, &r)
			if tst < ra || (tst == ra && r <= w0.w[k-1]) {
				break
			}
			attemp-- /* refine guess */
			ra += ldy
		}
		m = k - y0 + 1
		if attemp > 0 { /* do partial subtraction */
			borrow = 0
			for i = 0; i < y0; i++ {
				borrow = muldiv(attemp, y.w[i], borrow, Mr_mip.base, &dig)
				if w0.w[m+i] < dig { /* set borrow */
					borrow++
					w0.w[m+i] += (Mr_mip.base - dig)
				} else {
					w0.w[m+i] -= dig
				}
				if w0.w[k+1] < borrow { /* whoops! - over did it */
					w0.w[k+1] = 0
					carry = 0
					for i = 0; i < y0; i++ { /* compensate for error ... */
						psum = w0.w[m+i] + y.w[i] + carry
						carry = 0
						if psum >= Mr_mip.base {
							carry = 1
							psum -= Mr_mip.base
						}
						w0.w[m+i] = psum
					}
					attemp-- /* ... and adjust guess */
				} else {
					w0.w[k+1] -= borrow
				}
			}
			if k == w00-1 && attemp == 0 {
				w00--
			} else if y != z {
				z.w[m] = attemp
			}
		}
	}
	if y != z {
		z.len = uint32(w00-y0+1) | sz
	} /* set sign and length of result */

	w0.len = uint32(y0)

	mr_lzero(y)
	mr_lzero(z)

	if x != z {
		mr_lzero(w0)
		if d != 1 {
			mr_sdiv(w0, d, x)
		} else {
			copy(w0, x)
		}
		if x.len != 0 {
			x.len |= sx
		}
	}
	if d != 1 {
		mr_sdiv(y, d, y)
	}

	y.len |= sy
	Mr_mip.check = check

	Mr_mip.depth--
}

func mr_shift(x Big, n int, w Big) { /* set w=x.(mr_base^n) by shifting */
	var s uint32
	var i, bl int
	//var gw []uint32 = w.w

	if Mr_mip.ERNUM != 0 {
		return
	}
	copy(x, w)
	if w.len == 0 || n == 0 {
		return
	}
	MR_IN(33)

	//if mr_notint(w) {mr_berror(MR_ERR_INT_OP)}
	s = w.len & (1 << 31)
	bl = int(w.len&(1<<31-1)) + n
	if bl <= 0 {
		zero(w)
		Mr_mip.depth--
		return
	}
	//if bl>Mr_mip.nib && Mr_mip.check {mr_berror(MR_ERR_OVERFLOW)}
	if Mr_mip.ERNUM != 0 {
		Mr_mip.depth--
		return
	}
	if n > 0 {
		//var aaaa []uint32 =
		w.w = append(w.w, make([]uint32,bl-len(w.w))...)

		for i = bl - 1; i >= n; i-- {

			w.w[i] = w.w[i-n]
		}
		for i = 0; i < n; i++ {
			w.w[i] = 0
		}
	} else {
		n = -n
		for i = 0; i < bl; i++ {
			w.w[i] = w.w[i+n]
		}
		for i = 0; i < n; i++ {
			w.w[bl+i] = 0
		}
	}
	w.len = uint32(bl) | s
	Mr_mip.depth--
}

func redc(x, y Big) { /* Montgomery's REDC function p. 520 */
	/* also used to convert n-residues back to normal form */
	var carry, delay_carry uint32
	//var w0g,mg []uint32
	var ndash ,m uint32
	var i, j, rn, rn2 int
	var w0, modulus Big
	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(82)

	w0 = Mr_mip.w0
	modulus = Mr_mip.modulus
	ndash=Mr_mip.ndash

	copy(x, w0)
	if Mr_mip.MONTY == 0 {
		Divide(w0, modulus, modulus)
		copy(w0, y)
		Mr_mip.depth--
		return
	}
	delay_carry = 0
	rn = int(modulus.len)
	rn2 = rn + rn

	if Mr_mip.base == 0 {
		//mg=modulus.w
		//w0g=w0.w
		if rn2 > len(w0.w){
			w0.w = append(w0.w, make([]uint32,rn2 - len(w0.w))...)
		}
		for i = 0; i < rn; i++ {
			m=ndash*w0.w[i]
			carry = 0 /* around the loop, w0[i]=0    */

			for j = 0; j < rn; j++ {
				muldvd2(m,modulus.w[j],&carry,&w0.w[i+j]);
			}
			w0.w[rn+i] += delay_carry
			if w0.w[rn+i] < delay_carry {
				delay_carry = 1
			} else {
				delay_carry = 0
			}
			w0.w[rn+i] += carry
			if w0.w[rn+i] < carry {
				delay_carry = 1
			}
		}
	} else {
		for i = 0; i < rn; i++ {
			//muldiv(w0.w[i],ndash,0,Mr_mip.base,&m)
			carry = 0
			for j = 0; j < rn; j++ {
				//carry=muldiv(modulus.w[j],m,w0.w[i+j]+carry,Mr_mip.base,&w0.w[i+j]);
			}
			w0.w[rn+i] += (delay_carry + carry)
			delay_carry = 0
			if w0.w[rn+i] >= Mr_mip.base {
				w0.w[rn+i] -= Mr_mip.base
				delay_carry = 1
			}
		}
	}
	if rn2 > len(w0.w)-1{
		w0.w = append(w0.w, make([]uint32,rn2+1 - len(w0.w))...)
	}
	w0.w[rn2] = delay_carry
	w0.len = uint32(rn2 + 1)
	mr_shift(w0, (-rn), w0)
	mr_lzero(w0)

	if mr_compare(w0, modulus) >= 0 {
		mr_psub(w0, modulus, w0)
	}
	copy(w0, y)
	Mr_mip.depth--
}

func exsign(x Big) int { /* extract sign of big/flash number */
	if (x.len & (1 << 31)) == 0 {
		return 1
	} else {
		return -1
	}
}

func insign(s int, x Big) {
	if x.len == 0 {
		return
	}
	if s < 0 {
		x.len |= (1 << 31)
	} else {
		x.len &= (1<<31 - 1)
	}
}


func copy(x, y Big) { /* copy x to y: y=x  */
	var i, nx int
	//var gx, gy []uint32
	if x == y || y == nil {
		return
	}

	if x == nil {
		zero(y)
		return
	}

	//ny = mr_lent(y)
	nx = mr_lent(x)

	//gx = x.w
	if len(y.w) < nx{
		y.w = append(y.w, make([]uint32,nx-len(y.w))...)
	}
	y.w = make([]uint32,nx)

	//for i = nx; i < ny; i++ {
	//	y.w[i] = 0
	//}

	y.len = x.len
	for i = 0; i < nx; i++ {
		y.w[i] = x.w[i]
	}
}
func uconvert(n uint32, x Big) { /*  convert unsigned integer n to big number format  */
	var m int

	zero(x)
	if n == 0 {
		return
	}
	m = 0
	if Mr_mip.base == 0 {
		if len(x.w)<=m{
			x.w = make([]uint32,m+1,m+1)
			x.w[m] = uint32(n)
		}else{
			x.w[m] = uint32(n)
		}
		m++
	} else {
		for n > 0 {
			x.w[m] = uint32(n) % Mr_mip.base
			m++
			n = uint32(uint32(n) / Mr_mip.base)
		}
	}
	x.len = uint32(m)
}

func convert(n int, x Big) { /*  convert signed integer n to big number format  */
	var s uint32
	if n == 0 {
		zero(x)
		return
	}
	s = 0
	if n < 0 {
		s = 1 << 31
		n = -n
	}
	uconvert(uint32(n), x)
	x.len |= s
}

func size(x Big) int {
	var n, m int
	var s uint32
	if x == nil {
		return 0
	}
	s = x.len & (1 << 31)
	m = int(x.len & (1<<31 - 1))
	if m == 0 {
		return 0
	}
	if m == 1 && x.w[0] < uint32(1<<30) {
		n = int(x.w[0])

	} else {
		n = 1 << 30
	}
	if s == 1<<31 {
		return (-n)
	}
	return n
}

func mr_notint(x Big) bool { /* returns TRUE if x is Flash */

	if (((x.len & (1<<31 - 1)) >> 16) & (0xffff)) != 0 {
		return true
	}
	return false
}

func mr_padd(x,y,z Big) {
	/*  add two  big numbers, z=x+y where *
   *  x and y are positive              */
	var i, lx, ly, lz, la int
	var carry, psum uint32
	//var gx, gy, gz []uint32

	lx = int(x.len)
	ly = int(y.len)

	if ly > lx {
		lz = ly
		la = lx
		if x != z {
			copy(y, z)
		} else {
			la = ly
		}
	} else {
		lz = lx
		la = ly
		if y != z {
			copy(x, z)
		} else {
			la = lx
		}
	}
	carry = 0
	z.len = uint32(lz)
	//z.w = make([]uint32,z.len,z.len)

	if lz < Mr_mip.nib || (Mr_mip.check == 0) {
		z.w = append(z.w, 0)
		z.len++
	}
	//gx = x.w
	//gy = y.w
	//gz = z.w

	if Mr_mip.base == 0 {
		for i = 0; i < la; i++ { /* add by columns to length of the smaller number */
			psum = x.w[i] + y.w[i] + carry
			if psum > x.w[i] {
				carry = 0
			} else if psum < x.w[i] {
				carry = 1
			}
			z.w[i] = psum
		}
		if lz > len(x.w){
			x.w = append(x.w,make([]uint32,lz-len(x.w))...)
		}
		if lz > len(y.w){
			y.w = append(y.w,make([]uint32,lz-len(y.w))...)
		}
		for ; i < lz && carry > 0; i++ { /* add by columns to the length of larger number (if there is a carry) */
			psum = x.w[i] + y.w[i] + carry
			if psum > x.w[i] {
				carry = 0
			} else if psum < x.w[i] {
				carry = 1
			}
			z.w[i] = psum
		}
		if carry!=0 { /* carry left over - possible overflow */
			if (Mr_mip.check != 0) && i >= Mr_mip.nib {
				//mr_berror(MR_ERR_OVERFLOW);
				return
			}
			z.w[i] = carry
		}
	} else {
		for i = 0; i < la; i++ { /* add by columns */
			psum = x.w[i] + y.w[i] + carry
			carry = 0
			if psum >= Mr_mip.base { /* set carry */
				carry = 1
				psum -= Mr_mip.base
			}
			z.w[i] = psum
		}
		for ; i < lz && carry > 0; i++ {
			psum = x.w[i] + y.w[i] + carry
			carry = 0
			if psum >= Mr_mip.base { /* set carry */
				carry = 1
				psum -= Mr_mip.base
			}
			z.w[i] = psum
		}
		if carry!=0 { /* carry left over - possible overflow */
			if (Mr_mip.check != 0) && i >= Mr_mip.nib {
				//mr_berror(MR_ERR_OVERFLOW);
				return
			}
			z.w[i] = carry
		}
	}
	if int(z.len-1)<=len(z.w){
		z.w = append(z.w,0)
	}
	if z.w[z.len-1] == 0 {
		z.len--
	}
}

func Multiply(x,y,z Big) { /*  multiply two big numbers: z=x.y  */
	var i, xl, yl, j, ti int
	var carry, sz uint32
	//k := x.len+y.len
	var w0 Big


	if Mr_mip.ERNUM!=0 {
		return
	}
	if y.len == 0 || x.len == 0 {
		zero(z)
		return
	}

	if x != Mr_mip.w5 && y != Mr_mip.w5 && z == Mr_mip.w5 {
		w0 = Mr_mip.w5
	} else {
		w0 = Mr_mip.w0
	} /* local pointer */

	MR_IN(5)

	if mr_notint(x) || mr_notint(y) {
		//mr_berror(MR_ERR_INT_OP)
		Mr_mip.depth--
		return
	}

	sz = (x.len & (1 << 31)) ^ (y.len & (1 << 31))
	xl = (int)(x.len & (1<<31 - 1))
	yl = (int)(y.len & (1<<31 - 1))
	zero(w0)
	if Mr_mip.check!=0 {
		if (xl + yl) > Mr_mip.nib {
			//mr_berror(3)
			Mr_mip.depth--
			return
		}
	}

	if Mr_mip.base == 0 {
		//var xg, yg, w0g []uint32
		//xg = x.w
		//yg = y.w
		//w0g = w0.w
		if x == y && xl > 5 { /* fast squaring */
			if yl + xl > len(w0.w){
				w0.w=append(w0.w, make([]uint32,yl+xl-len(w0.w))...)
			}
			for i = 0; i < xl-1; i++ { /* long multiplication */
				carry = 0
				for j = i + 1; j < xl; j++ { /* Only do above the diagonal */
					muldvd2(x.w[i],x.w[j],&carry,&w0.w[i+j])
				}
				w0.w[xl+i] = carry
			}
			w0.len = uint32(xl + xl - 1)
			mr_padd(w0, w0, w0) /* double it */
			carry = 0
			for i = 0; i < xl; i++ { /* add in squared elements */
				ti = i + i
				muldvd2(x.w[i],x.w[i],&carry,&w0.w[ti])
				w0.w[ti+1] += carry
				if w0.w[ti+1] < carry {
					carry = 1
				} else {
					carry = 0
				}
			}

		} else {
			if yl + xl > len(w0.w){
				w0.w=append(w0.w, make([]uint32,yl+xl-len(w0.w))...)
			}

			for i = 0; i < xl; i++ { /* long multiplication */
				/* inline - substitutes for loop below */

				carry = 0
				for j = 0; j < yl; j++ {
					muldvd2(x.w[i],y.w[j],&carry,&w0.w[i+j])
				}
				w0.w[yl+i] = carry
			}
			w0.len = uint32(xl + xl - 1)
		}
	} else {
		if x == y && xl > 5 { /* squaring can be done nearly twice as fast */
			for i = 0; i < xl-1; i++ { /* long multiplication */
				carry = 0
				for j = i + 1; j < xl; j++ { /* Only do above the diagonal */

					carry=muldiv(x.w[i],x.w[j],w0.w[i+j]+carry,Mr_mip.base,&w0.w[i+j])

				}
				w0.w[xl+i] = carry
			}
			w0.len = uint32(xl + xl - 1)
			mr_padd(w0, w0, w0) /* double it */
			carry = 0
			for i = 0; i < xl; i++ { /* add in squared elements */
				ti = i + i

				carry=muldiv(x.w[i],x.w[i],w0.w[ti]+carry,Mr_mip.base,&w0.w[ti])

				w0.w[ti+1] += carry
				carry = 0
				if w0.w[ti+1] >= Mr_mip.base {
					carry = 1
					w0.w[ti+1] -= Mr_mip.base
				}
			}
		} else {
			for i = 0; i < xl; i++ { /* long multiplication */
				carry = 0
				for j = 0; j < yl; j++ { /* multiply each digit of y by x[i] */
					carry=muldiv(x.w[i],y.w[j],w0.w[i+j]+carry,Mr_mip.base,&w0.w[i+j])
				}
				w0.w[yl+i] = carry
			}
		}
	}
	w0.len = sz | uint32(xl + yl) /* set length and sign of result */
	mr_lzero(w0)
	copy(w0, z)
	Mr_mip.depth--
}

func mr_select(x Big, d int, y Big, z Big) { /* perform required add or subtract operation */
	var sx, sy, sz, jf, xgty int

	if mr_notint(x) || mr_notint(y) {
		//mr_berror(MR_ERR_INT_OP);
		return
	}

	sx = exsign(x)
	sy = exsign(y)
	sz = 0
	x.len &= 1<<31 - 1 /* force operands to be positive */
	y.len &= 1<<31 - 1
	xgty = mr_compare(x, y)
	jf = (1 + sx) + (1+d*sy)/2
	switch jf { /* branch according to signs of operands */
	case 0:
		if xgty >= 0 {
			mr_padd(x, y, z)
		} else {
			mr_padd(y, x, z)
		}
		sz = -1
		break
	case 1:
		if xgty <= 0 {
			mr_psub(y, x, z)
			sz = 1
		} else {
			mr_psub(x, y, z)
			sz = -1
		}
		break
	case 2:
		if xgty >= 0 {
			mr_psub(x, y, z)
			sz = 1
		} else {
			mr_psub(y, x, z)
			sz = -1
		}
		break
	case 3:
		if xgty >= 0 {
			mr_padd(x, y, z)
		} else {
			mr_padd(y, x, z)
		}
		sz = 1
		break
	}
	if sz < 0 {
		z.len ^= 1 << 31
	} /* set sign of result         */
	if x != z && sx < 0 {
		x.len ^= 1 << 31
	} /* restore signs to operands  */
	if y != z && y != x && sy < 0 {
		y.len ^= 1 << 31
	}
}

func Add(x, y, z Big) { /* add two signed big numbers together z=x+y */

	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(27)

	mr_select(x, 1, y, z)

	Mr_mip.depth--
}

func qdiv(u, v uint64) uint32 { /* fast division - small quotient expected.  */
	var lq uint64 = u
	var x uint64 = u

	x -= v
	if x < v {
		return 1
	}
	x -= v
	if x < v {
		return 2
	}
	x -= v
	if x < v {
		return 3
	}
	x -= v
	if x < v {
		return 4
	}
	x -= v
	if x < v {
		return 5
	}
	x -= v
	if x < v {
		return 6
	}
	x -= v
	if x < v {
		return 7
	}
	x -= v
	if x < v {
		return 8
	}

	/* do it the hard way! */
	lq = 8 + x/v
	if lq >= (1 << 31) {
		return 0
	}
	return uint32(lq)
}

func subtract(x, y, z Big) { /* subtract two big signed numbers z=x-y */
	if Mr_mip.ERNUM != 0 {
		return
	}
	MR_IN(28)
	mr_select(x, -1, y, z)
	Mr_mip.depth--
}

func negify(x, y Big) { /* negate a big/flash variable: y=-x */
	copy(x, y)
	if y.len != 0 {
		y.len ^= 1 << 31
	}
}

func mad(x, y, z, w, q, r Big) { /* Multiply, Add and Divide; q=(x*y+z)/w remainder r   *
	 * returns remainder only if w=q, quotient only if q=r *
	 * add done only if x, y and z are distinct.           */
	var check int
	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(24)
	if w == r {
		//mr_berror(MR_ERR_BAD_PARAMETERS);
		Mr_mip.depth--
		return
	}
	check = Mr_mip.check
	Mr_mip.check = 0 /* turn off some error checks */

	Multiply(x, y, Mr_mip.w0)
	if x != z && y != z {
		Add(Mr_mip.w0, z, Mr_mip.w0)
	}

	Divide(Mr_mip.w0, w, q)
	if q != r {
		copy(Mr_mip.w0, r)
	}
	Mr_mip.check = check
	Mr_mip.depth--
}

type doubleword struct { //c语言的union我不知道该怎么转换好
	d uint64
	h [2]uint32
}
func (p *doubleword) setDFromH() {
	p.d = uint64(p.h[1])<<32 + uint64(p.h[0])
}

func xgcd(x, y, xd, yd, z Big) int {
	/* greatest common divisor by Euclids method  *
	 * extended to also calculate xd and yd where *
	 *      z = x.xd + y.yd = gcd(x,y)            *
	 * if xd, yd not distinct, only xd calculated *
	 * z only returned if distinct from xd and yd *
	 * xd will always be positive, yd negative    */

	var s, n, iter int
	var r, a, b, c, d, q, m, sr uint32

	//union doubleword uu,vv 源码的类型
	var uu, vv doubleword
	var u, v, lr uint64 //u long long c源码的类型难懂

	var last, dplus int = 1, 1
	var t Big

	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(30)

	copy(x, Mr_mip.w1)
	copy(y, Mr_mip.w2)
	s = exsign(Mr_mip.w1)
	insign(1, Mr_mip.w1)
	insign(1, Mr_mip.w2)
	convert(1, Mr_mip.w3)
	zero(Mr_mip.w4)
	last = 0
	a, b, c, d = 0, 0, 0, 0
	iter = 0
	var ccc int = 0
	for size(Mr_mip.w2) != 0 {
		ccc++

		if b == 0 { /* update Mr_mip.w1 and Mr_mip.w2 */

			Divide(Mr_mip.w1, Mr_mip.w2, Mr_mip.w5)
			t = Mr_mip.w1
			Mr_mip.w1 = Mr_mip.w2
			Mr_mip.w2 = t /* swap(Mr_mip.w1,Mr_mip.w2) */
			Multiply(Mr_mip.w4, Mr_mip.w5, Mr_mip.w0)
			Add(Mr_mip.w3, Mr_mip.w0, Mr_mip.w3)
			t = Mr_mip.w3
			Mr_mip.w3 = Mr_mip.w4
			Mr_mip.w4 = t /* swap(xd,yd) */
			iter++

		} else {

			/* printf("a= %I64u b= %I64u c= %I64u  d= %I64u \n",a,b,c,d);   */

			mr_pmul(Mr_mip.w1, c, Mr_mip.w5) /* c*w1 */
			mr_pmul(Mr_mip.w1, a, Mr_mip.w1) /* a*w1 */
			mr_pmul(Mr_mip.w2, b, Mr_mip.w0) /* b*w2 */
			mr_pmul(Mr_mip.w2, d, Mr_mip.w2) /* d*w2 */

			if dplus == 0 {
				mr_psub(Mr_mip.w0, Mr_mip.w1, Mr_mip.w1) /* b*w2-a*w1 */
				mr_psub(Mr_mip.w5, Mr_mip.w2, Mr_mip.w2) /* c*w1-d*w2 */
			} else {
				mr_psub(Mr_mip.w1, Mr_mip.w0, Mr_mip.w1) /* a*w1-b*w2 */
				mr_psub(Mr_mip.w2, Mr_mip.w5, Mr_mip.w2) /* d*w2-c*w1 */
			}
			mr_pmul(Mr_mip.w3, c, Mr_mip.w5)
			mr_pmul(Mr_mip.w3, a, Mr_mip.w3)
			mr_pmul(Mr_mip.w4, b, Mr_mip.w0)
			mr_pmul(Mr_mip.w4, d, Mr_mip.w4)

			if a == 0 {
				copy(Mr_mip.w0, Mr_mip.w3)
			} else {
				mr_padd(Mr_mip.w3, Mr_mip.w0, Mr_mip.w3)
			}
			mr_padd(Mr_mip.w4, Mr_mip.w5, Mr_mip.w4)
		}
		if (Mr_mip.ERNUM != 0) || size(Mr_mip.w2) == 0 {
			break
		}

		n = int(Mr_mip.w1.len)
		if n == 1 {
			last = 1
			u = uint64(Mr_mip.w1.w[0])
			v = uint64(Mr_mip.w2.w[0])
		} else {
			if Mr_mip.w1.len < 2{
				Mr_mip.w1.w = append(Mr_mip.w1.w, 0,0)
			}
			if Mr_mip.w2.len < 2{
				Mr_mip.w2.w = append(Mr_mip.w2.w, 0,0)
			}

			m = Mr_mip.w1.w[n-1] + 1

			if Mr_mip.base == 0 {
				if n > 2 && m != 0 {
					uu.h[1] = muldvm(Mr_mip.w1.w[n-1], Mr_mip.w1.w[n-2], m, &sr)
					uu.h[0] = muldvm(sr, Mr_mip.w1.w[n-3], m, &sr)
					vv.h[1] = muldvm(Mr_mip.w2.w[n-1], Mr_mip.w2.w[n-2], m, &sr)
					vv.h[0] = muldvm(sr, Mr_mip.w2.w[n-3], m, &sr)
				} else {
					uu.h[1] = Mr_mip.w1.w[n-1]
					uu.h[0] = Mr_mip.w1.w[n-2]
					vv.h[1] = Mr_mip.w2.w[n-1]
					vv.h[0] = Mr_mip.w2.w[n-2]
					if n == 2 {
						last = 1
					}
				}
				uu.setDFromH()
				vv.setDFromH()
				u = uint64(uu.d)
				v = uint64(vv.d)

			} else {

				if n > 2 { /* squeeze out as much significance as possible */
					u = uint64(muldiv(Mr_mip.w1.w[n-1], Mr_mip.base, Mr_mip.w1.w[n-2], m, &sr))
					u = u*uint64(Mr_mip.base + muldiv(sr, Mr_mip.base, Mr_mip.w1.w[n-3], m, &sr))
					v = uint64(muldiv(Mr_mip.w2.w[n-1], Mr_mip.base, Mr_mip.w2.w[n-2], m, &sr))
					v = v*uint64(Mr_mip.base + muldiv(sr, Mr_mip.base, Mr_mip.w2.w[n-3], m, &sr))
				} else {
					u = uint64(uint32(Mr_mip.base*Mr_mip.w1.w[n-1] + Mr_mip.w1.w[n-2]))
					v = uint64(uint32(Mr_mip.base*Mr_mip.w2.w[n-1] + Mr_mip.w2.w[n-2]))
					last = 1
				}
			}
		}
		dplus = 1
		a = 1
		b = 0
		c = 0
		d = 1
		for true { /* work only with most significant piece */
			if last != 0 {
				if v == 0 {
					break
				}
				q = qdiv(u, v)
				if q == 0 {
					break
				}
			} else {
				if dplus != 0 {
					if v-uint64(c) == 0 || v+uint64(d) == 0 {
						break
					}

					q = qdiv(u+uint64(a), v-uint64(c))

					if q == 0 {
						break
					}

					if q != qdiv(u-uint64(b), v+uint64(d)) {
						break
					}
				} else {
					if v+uint64(c) == 0 || v-uint64(d) == 0 {
						break
					}
					q = qdiv(u-uint64(a), v+uint64(c))
					if q == 0 {
						break
					}
					if q != qdiv(u+uint64(b), v-uint64(d)) {
						break
					}
				}
			}

			if q == 1 {
				if uint32(b+d) >= (1 << 31) {
					break
				}
				r = a + c
				a = c
				c = r
				r = b + d
				b = d
				d = r
				lr = u - v
				u = v
				v = lr
			} else {
				if q >= (1<<31-b)/d {
					break
				}
				r = a + q*c
				a = c
				c = r
				r = b + q*d
				b = d
				d = r
				lr = u - uint64(q)*v
				u = v
				v = lr
			}
			iter++
			dplus = 1 - dplus
		}
		iter %= 2

	}

	if s == -1 {
		iter++
	}
	if iter%2 == 1 {
		subtract(y, Mr_mip.w3, Mr_mip.w3)
	}

	if xd != yd {
		negify(x, Mr_mip.w2)
		mad(Mr_mip.w2, Mr_mip.w3, Mr_mip.w1, y, Mr_mip.w4, Mr_mip.w4)
		copy(Mr_mip.w4, yd)
	}
	copy(Mr_mip.w3, xd)
	if z != xd && z != yd {
		copy(Mr_mip.w1, z)
	}

	Mr_mip.depth--
	return (size(Mr_mip.w1))
}

func invmodp(x, y, z Big) int {
	var gcd int

	MR_IN(213)
	gcd = xgcd(x, y, z, z, z)
	Mr_mip.depth--
	return gcd
}

func nres(x, y Big) { /* convert x to n-residue format */

	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(81)

	if size(Mr_mip.modulus) == 0 {
		mr_berror(20)
		Mr_mip.depth--
		return
	}
	copy(x, y)
	Divide(y, Mr_mip.modulus, Mr_mip.modulus)
	if size(y) < 0 {
		Add(y, Mr_mip.modulus, y)
	}
	if Mr_mip.MONTY == 0 {
		Mr_mip.depth--
		return
	}
	Mr_mip.check = 0

	mr_shift(y, int(Mr_mip.modulus.len), Mr_mip.w0)
	Divide(Mr_mip.w0, Mr_mip.modulus, Mr_mip.modulus)
	Mr_mip.check = 1
	copy(Mr_mip.w0, y)

	Mr_mip.depth--
}

func nres_modmult(x, y, w Big) { /* Modular multiplication using n-residues w=x*y mod n */
	if (x == nil || x.len == 0) && x == w {
		return
	}
	if (y == nil || y.len == 0) && y == w {
		return
	}
	if y == nil || x == nil || x.len == 0 || y.len == 0 {
		zero(w)
		return
	}
	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(83)

	Mr_mip.check = 0
	Multiply(x, y, Mr_mip.w0)
	redc(Mr_mip.w0, w)
	Mr_mip.check = 1
	Mr_mip.depth--
}

func nres_moddiv(x, y, w Big) int { /* Modular division using n-residues w=x/y mod n */
	var gcd int

	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(85)

	if x == y { /* Illegal parameter usage */
		mr_berror(7) //错误函数，未实现
		Mr_mip.depth--

		return 0
	}
	redc(y, Mr_mip.w6)
	gcd = invmodp(Mr_mip.w6, Mr_mip.modulus, Mr_mip.w6)

	if gcd != 1 {
		zero(w)
	} else {
		nres(Mr_mip.w6, Mr_mip.w6)
		nres_modmult(x, Mr_mip.w6, w)

	}
	Mr_mip.depth--
	return gcd
}

func mr_abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func nres_modadd(x, y, w Big) { /* modular addition */
	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(90)
	mr_padd(x, y, w)
	if mr_compare(w, Mr_mip.modulus) >= 0 {
		mr_psub(w, Mr_mip.modulus, w)
	}
	Mr_mip.depth--
}

func nres_negate(x, w Big) {
	if size(x) == 0 {
		zero(w)
		return
	}
	if Mr_mip.ERNUM != 0 {
		return
	}
	MR_IN(92)
	mr_psub(Mr_mip.modulus, x, w)
	Mr_mip.depth--
}

func nres_premult(x Big, k int, w Big) { /* multiply n-residue by small ordinary integer */

	var sign int = 0
	if k == 0 {
		zero(w)
		return
	}
	if k < 0 {
		k = -k
		sign = 1
	}
	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(102)

	if k <= 6 {
		switch k {
		case 1:
			copy(x, w)
			break
		case 2:
			nres_modadd(x, x, w)
			break
		case 3:
			nres_modadd(x, x, Mr_mip.w0)
			nres_modadd(x, Mr_mip.w0, w)
			break
		case 4:
			nres_modadd(x, x, w)
			nres_modadd(w, w, w)
			break
		case 5:
			nres_modadd(x, x, Mr_mip.w0)
			nres_modadd(Mr_mip.w0, Mr_mip.w0, Mr_mip.w0)
			nres_modadd(x, Mr_mip.w0, w)
			break
		case 6:
			nres_modadd(x, x, w)
			nres_modadd(w, w, Mr_mip.w0)
			nres_modadd(w, Mr_mip.w0, w)
			break
		}
		if sign == 1 {
			nres_negate(w, w)
		}
		Mr_mip.depth--
		return
	}
	mr_pmul(x, uint32(k), Mr_mip.w0)
	Divide(Mr_mip.w0, Mr_mip.modulus, Mr_mip.modulus)
	copy(Mr_mip.w0, w)
	if sign == 1 {
		nres_negate(w, w)
	}
	Mr_mip.depth--
}

func epoint_getrhs(x, y Big) { /* x and y must be different */

	/* find x^3+Ax+B */

	nres_modmult(x, x, y)

	nres_modmult(y, x, y)
	if mr_abs(Mr_mip.Asize) == (1 << 30) {
		nres_modmult(x, Mr_mip.A, Mr_mip.w1)
	} else {
		nres_premult(x, Mr_mip.Asize, Mr_mip.w1)
	}
	nres_modadd(y, Mr_mip.w1, y)
	if mr_abs(Mr_mip.Bsize) == (1 << 30) {
		nres_modadd(y, Mr_mip.B, y)
	} else {
		convert(Mr_mip.Bsize, Mr_mip.w1)
		nres(Mr_mip.w1, Mr_mip.w1)
		nres_modadd(y, Mr_mip.w1, y)
	}
}

func subdiv(x Big, n int, z Big) int {
	/*  subDivide a big number by an int   z=x/n  *
	*  returns int remainder                     */
	var sx, lsb uint32
	var r, i, msb int
	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(10)

	if mr_notint(x) {
		mr_berror(12)
	}

	if n == 0 {
		mr_berror(2)
	}
	if Mr_mip.ERNUM != 0 {
		Mr_mip.depth--
		return 0
	}

	if x.len == 0 {
		zero(z)
		Mr_mip.depth--
		return 0
	}
	if n == 1 /* special case */ {
		copy(x, z)
		Mr_mip.depth--
		return 0
	}
	sx = x.len & (1 << 31)
	if n == 2 && Mr_mip.base == 0 { /* fast division by 2 using shifting */
		/* I don't want this code upsetting the compiler ... */
		/* Mr_mip.base==0 can't happen with MR_NOFULLWIDTH  */
		copy(x, z)
		msb = int((z.len & (1<<31 - 1)) - 1)
		r = int(z.w[0] & 1)
		for i = 0; ; i++ {
			z.w[i] >>= 1
			if i == msb {
				if z.w[i] == 0 {
					mr_lzero(z)
				}
				break
			}
			lsb = z.w[i+1] & 1
			z.w[i] |= lsb << 31
		}

		Mr_mip.depth--
		if sx == 0 {
			return r
		} else {
			return -r
		}

	}

	if n < 0 {
		n = (-n)

		r = int(mr_sdiv(x, uint32(n), z))

		if z.len != 0 {
			z.len ^= 1 << 31
		}
	} else {
		r = int(mr_sdiv(x, uint32(n), z))
	}

	Mr_mip.depth--
	if sx == 0 {
		return r
	} else {
		return -r
	}
}

func remain(x Big, n int) int { /* return integer remainder when x Divided by n */
	var r int
	var sx uint32

	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(88)

	sx = x.len & (1 << 31)

	if n == 2 && Mr_mip.base%2 == 0 { /* fast odd/even check if base is even */
		Mr_mip.depth--
		if int(x.w[0]%2) == 0 {
			return 0
		} else {
			if sx == 0 {
				return 1
			} else {
				return (-1)
			}
		}
	}
	if n == 8 && Mr_mip.base%8 == 0 { /* fast check */
		Mr_mip.depth--
		r = int(x.w[0] % 8)
		if sx != 0 {
			r = -r
		}
		return r
	}

	copy(x, Mr_mip.w0)
	r = subdiv(Mr_mip.w0, n, Mr_mip.w0)
	Mr_mip.depth--
	return r
}

func jack(a, n Big) int { /* find jacobi symbol (a/n), for positive odd n */
	var w Big
	var nm8, onm8, t int

	if Mr_mip.ERNUM != 0 || size(a) == 0 || size(n) < 1 {
		return 0
	}
	MR_IN(3)

	t = 1
	copy(n, Mr_mip.w2)
	nm8 = remain(Mr_mip.w2, 8)
	if nm8%2 == 0 {
		Mr_mip.depth--
		return 0
	}

	if size(a) < 0 {
		if nm8%4 == 3 {
			t = -1
		}
		negify(a, Mr_mip.w1)
	} else {
		copy(a, Mr_mip.w1)
	}

	for size(Mr_mip.w1) != 0 {
		for remain(Mr_mip.w1, 2) == 0 {
			subdiv(Mr_mip.w1, 2, Mr_mip.w1)
			if nm8 == 3 || nm8 == 5 {
				t = -t
			}
		}
		if mr_compare(Mr_mip.w1, Mr_mip.w2) < 0 {
			onm8 = nm8
			w = Mr_mip.w1
			Mr_mip.w1 = Mr_mip.w2
			Mr_mip.w2 = w
			nm8 = remain(Mr_mip.w2, 8)
			if onm8%4 == 3 && nm8%4 == 3 {
				t = -t
			}
		}
		mr_psub(Mr_mip.w1, Mr_mip.w2, Mr_mip.w1)
		subdiv(Mr_mip.w1, 2, Mr_mip.w1)

		if nm8 == 3 || nm8 == 5 {
			t = -t
		}
	}

	Mr_mip.depth--
	if size(Mr_mip.w2) == 1 {
		return t
	}
	return 0
}

func incr(x Big, n int, z Big) { /* add int to big number: z=x+n */

	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(7)

	convert(n, Mr_mip.w0)
	mr_select(x, 1, Mr_mip.w0, z)

	Mr_mip.depth--
}

func premult(x Big, n int, z Big) { /* premultiply a big number by an int z=x.n */
	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(9)
	if mr_notint(x) {
		mr_berror(12)
		Mr_mip.depth--
		return
	}

	if n == 0 /* test for some special cases  */ {
		zero(z)
		Mr_mip.depth--
		return
	}
	if n == 1 {
		copy(x, z)
		Mr_mip.depth--
		return
	}
	if n < 0 {
		n = -n
		mr_pmul(x, uint32(n), z)
		if z.len != 0 {
			z.len ^= 1 << 31
		}
	} else {
		mr_pmul(x, uint32(n), z)
	}
	Mr_mip.depth--
}

func decr(x Big, n int, z Big) { /* subtract int from big number: z=x-n */

	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(8)

	convert(n, Mr_mip.w0)
	mr_select(x, -1, Mr_mip.w0, z)

	Mr_mip.depth--
}

func nres_sqroot(x, w Big) int { /* w=sqrt(x) mod p. This depends on p being prime! */
	var t, js int
	if Mr_mip.ERNUM != 0 {
		return 0
	}

	copy(x, w)
	if size(w) == 0 {
		return 1
	}

	MR_IN(100)

	redc(w, w) /* get it back into normal form */

	if size(w) == 1 /* square root of 1 is 1 */ {
		nres(w, w)
		Mr_mip.depth--
		return 1
	}

	if size(w) == 4 /* square root of 4 is 2 */ {
		convert(2, w)
		nres(w, w)
		Mr_mip.depth--
		return 1
	}

	if jack(w, Mr_mip.modulus) != 1 { /* Jacobi test */
		zero(w)
		Mr_mip.depth--
		return 0
	}

	js = Mr_mip.pmod8%4 - 2 /* 1 mod 4 or 3 mod 4 prime? */

	incr(Mr_mip.modulus, js, Mr_mip.w10)
	subdiv(Mr_mip.w10, 4, Mr_mip.w10) /* (p+/-1)/4 */

	if js == 1 { /* 3 mod 4 primes - do a quick and dirty sqrt(x)=x^(p+1)/4 mod p */
		nres(w, Mr_mip.w2)
		copy(Mr_mip.one, w)
		for true {
			/* Simple Right-to-Left exponentiation */
			//if Mr_mip.user != nil {
			//	*Mr_mip.user()
			//}
			if subdiv(Mr_mip.w10, 2, Mr_mip.w10) != 0 {
				nres_modmult(w, Mr_mip.w2, w)
			}
			if Mr_mip.ERNUM != 0 || size(Mr_mip.w10) == 0 {
				break
			}
			nres_modmult(Mr_mip.w2, Mr_mip.w2, Mr_mip.w2)
		}
	} else { /* 1 mod 4 primes */
		for t = 1; ; t++ { /* t=1.5 on average */
			if t == 1 {
				copy(w, Mr_mip.w4)
			} else {
				premult(w, t, Mr_mip.w4)
				Divide(Mr_mip.w4, Mr_mip.modulus, Mr_mip.modulus)
				premult(Mr_mip.w4, t, Mr_mip.w4)
				Divide(Mr_mip.w4, Mr_mip.modulus, Mr_mip.modulus)
			}

			decr(Mr_mip.w4, 4, Mr_mip.w1)
			if jack(Mr_mip.w1, Mr_mip.modulus) == js {
				break
			}
			if Mr_mip.ERNUM != 0 {
				break
			}
		}

		decr(Mr_mip.w4, 2, Mr_mip.w3)
		nres(Mr_mip.w3, Mr_mip.w3)
		nres_lucas(Mr_mip.w3, Mr_mip.w10, w, w) /* heavy lifting done here */
		if t != 1 {
			convert(t, Mr_mip.w11)
			nres(Mr_mip.w11, Mr_mip.w11)
			nres_moddiv(w, Mr_mip.w11, w)
		}
	}
	Mr_mip.depth--
	return 1
}

func logb2(x Big) int { /* returns number of bits in x */
	var xl, lg2 int
	var top uint32

	if (Mr_mip.ERNUM != 0) || size(x) == 0 {
		return 0
	}

	MR_IN(49)

	if Mr_mip.base == Mr_mip.base2 {

		xl = int(x.len & (1<<31 - 1))
		lg2 = Mr_mip.lg2b * (xl - 1)
		top = x.w[xl-1]
		for top >= 1 {
			lg2++
			top /= 2
		}
	} else {
		copy(x, Mr_mip.w0)
		insign(1, Mr_mip.w0)
		lg2 = 0
		for Mr_mip.w0.len > 1 {
			mr_sdiv(Mr_mip.w0, Mr_mip.base2, Mr_mip.w0)
			lg2 += Mr_mip.lg2b
		}
		for Mr_mip.w0.w[0] >= 1 {
			lg2++
			Mr_mip.w0.w[0] /= 2
		}
	}

	Mr_mip.depth--
	return lg2
}

func mr_testbit(x Big, n int) int {
	if n/Mr_mip.lg2b > len(x.w) - 1{
		x.w = append(x.w, make([]uint32,int(n/Mr_mip.lg2b)+1 - len(x.w))...)
	}
	if x.w[n/Mr_mip.lg2b]&(uint32(1)<<uint32(n%Mr_mip.lg2b)) > 0 {
		return 1
	}
	return 0
}

func nres_modsub(x, y, w Big) { /* modular subtraction */
	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(91)

	if mr_compare(x, y) >= 0 {
		mr_psub(x, y, w)
	} else {
		mr_psub(y, x, w)
		mr_psub(Mr_mip.modulus, w, w)
	}
	Mr_mip.depth--
}

func mr_shiftbits(x uint32, n int) uint32 {
	if n == 0 {
		return x
	}
	if n > 0 {
		x <<= uint32(n)
	} else {
		x >>= uint32(-n)
	}
	return x
}

func expb2(n int, x Big) { /* sets x=2^n */
	var r, p, i int

	if Mr_mip.ERNUM != 0 {
		return
	}
	convert(1, x)
	if n == 0 {
		return
	}

	MR_IN(149)

	if n < 0 {
		mr_berror(10)
		Mr_mip.depth--
		return
	}
	r = n / Mr_mip.lg2b
	p = n % Mr_mip.lg2b

	if Mr_mip.base == Mr_mip.base2 {

		mr_shift(x, r, x)
		x.w[x.len-1] = mr_shiftbits(x.w[x.len-1], p)

	} else {
		for i = 1; i <= r; i++ {
			mr_pmul(x, Mr_mip.base2, x)
		}
		mr_pmul(x, mr_shiftbits(uint32(1), p), x)
	}
	Mr_mip.depth--
}

func nres_lucas(p, r, vp, v Big) {
	var i, nb int

	if Mr_mip.ERNUM != 0 {
		return
	}

	MR_IN(107)

	if size(r) == 0 {
		zero(vp)
		convert(2, v)
		nres(v, v)
		Mr_mip.depth--
		return
	}
	if size(r) == 1 || size(r) == (-1) { /* note - sign of r doesn't matter */
		convert(2, vp)
		nres(vp, vp)
		copy(p, v)
		Mr_mip.depth--
		return
	}

	copy(p, Mr_mip.w3)

	convert(2, Mr_mip.w4)
	nres(Mr_mip.w4, Mr_mip.w4) /* w4=2 */

	copy(Mr_mip.w4, Mr_mip.w8)
	copy(Mr_mip.w3, Mr_mip.w9)

	copy(r, Mr_mip.w1)
	insign(1, Mr_mip.w1)
	decr(Mr_mip.w1, 1, Mr_mip.w1)

	if Mr_mip.base == Mr_mip.base2 {

		nb = logb2(Mr_mip.w1)
		for i = nb - 1; i >= 0; i-- {
			//if Mr_mip.user != nil {
			//	*Mr_mip.user()
			//}

			if mr_testbit(Mr_mip.w1, i) != 0 {
				nres_modmult(Mr_mip.w8, Mr_mip.w9, Mr_mip.w8)
				nres_modsub(Mr_mip.w8, Mr_mip.w3, Mr_mip.w8)
				nres_modmult(Mr_mip.w9, Mr_mip.w9, Mr_mip.w9)
				nres_modsub(Mr_mip.w9, Mr_mip.w4, Mr_mip.w9)

			} else {
				nres_modmult(Mr_mip.w9, Mr_mip.w8, Mr_mip.w9)
				nres_modsub(Mr_mip.w9, Mr_mip.w3, Mr_mip.w9)
				nres_modmult(Mr_mip.w8, Mr_mip.w8, Mr_mip.w8)
				nres_modsub(Mr_mip.w8, Mr_mip.w4, Mr_mip.w8)
			}
		}
	} else {
		expb2(logb2(Mr_mip.w1)-1, Mr_mip.w2)

		for (Mr_mip.ERNUM == 0) && size(Mr_mip.w2) != 0 { /* use binary method */
			if mr_compare(Mr_mip.w1, Mr_mip.w2) >= 0 { /* vp=v*vp-p, v=v*v-2 */
				nres_modmult(Mr_mip.w8, Mr_mip.w9, Mr_mip.w8)
				nres_modsub(Mr_mip.w8, Mr_mip.w3, Mr_mip.w8)
				nres_modmult(Mr_mip.w9, Mr_mip.w9, Mr_mip.w9)
				nres_modsub(Mr_mip.w9, Mr_mip.w4, Mr_mip.w9)
				subtract(Mr_mip.w1, Mr_mip.w2, Mr_mip.w1)
			} else { /* v=v*vp-p, vp=vp*vp-2 */
				nres_modmult(Mr_mip.w9, Mr_mip.w8, Mr_mip.w9)
				nres_modsub(Mr_mip.w9, Mr_mip.w3, Mr_mip.w9)
				nres_modmult(Mr_mip.w8, Mr_mip.w8, Mr_mip.w8)
				nres_modsub(Mr_mip.w8, Mr_mip.w4, Mr_mip.w8)
			}
			subdiv(Mr_mip.w2, 2, Mr_mip.w2)
		}
	}
	copy(Mr_mip.w9, v)
	if v != vp {
		copy(Mr_mip.w8, vp)
	}
	Mr_mip.depth--

}

func Epoint_set(x Big, y Big, cb int, p *Epoint) int {
	/* initialise a point on active ecurve            *
	 * if x or y == NULL, set to point at infinity    *
	 * if x==y, a y co-ordinate is calculated - if    *
	 * possible - and cb suggests LSB 0/1  of y       *
	 * (which "decompresses" y). Otherwise, check     *
	 * validity of given (x,y) point, ignoring cb.    *
	 * Returns TRUE for valid point, otherwise FALSE. */
	var valid int
	if Mr_mip.ERNUM != 0 {
		return 0
	}
	MR_IN(97)
	if x == nil || y == nil {
		copy(Mr_mip.one, p.X)
		copy(Mr_mip.one, p.Y)
		p.marker = 2
		Mr_mip.depth--
		return 1
	}
	/* find x^3+Ax+B */
	nres(x, p.X)
	epoint_getrhs(p.X, Mr_mip.w3)
	valid = 0

	if x != y { /* compare with y^2 */
		nres(y, p.Y)
		nres_modmult(p.Y, p.Y, Mr_mip.w1)
		if mr_compare(Mr_mip.w1, Mr_mip.w3) == 0 {
			valid = 1
		}
	} else {
		/* no y supplied - calculate one. Find square root */
		valid = nres_sqroot(Mr_mip.w3, p.Y)
		/* check LSB - have we got the right root? */
		redc(p.Y, Mr_mip.w1)
		if remain(Mr_mip.w1, 2) != cb {
			mr_psub(Mr_mip.modulus, p.Y, p.Y)
		}
	}
	if valid != 0 {
		p.marker = 1
		Mr_mip.depth--
		return 1
	}
	Mr_mip.depth--
	return 0
}

func epoint_norm(p *Epoint) int { /* normalise a point */

	if Mr_mip.coord == 1 {
		return 1
	}
	if p.marker != 0 {
		return 1
	}
	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(117)

	copy(Mr_mip.one, Mr_mip.w8)

	if nres_moddiv(Mr_mip.w8, p.Z, Mr_mip.w8) > 1 { /* 1/Z  */

		Epoint_set(nil, nil, 0, p)
		mr_berror(28)
		Mr_mip.depth--
		return 0
	}

	nres_modmult(Mr_mip.w8, Mr_mip.w8, Mr_mip.w1) /* 1/ZZ */
	nres_modmult(p.X, Mr_mip.w1, p.X)             /* X/ZZ */
	nres_modmult(Mr_mip.w1, Mr_mip.w8, Mr_mip.w1) /* 1/ZZZ */
	nres_modmult(p.Y, Mr_mip.w1, p.Y)             /* Y/ZZZ */

	copy(Mr_mip.one, p.Z)
	p.marker = 1
	Mr_mip.depth--
	return 1
}

func Epoint_get(p *Epoint, x Big, y Big) int {
	var lsb int

	if p.marker == 2 {
		zero(x)
		zero(y)
		return 0
	}
	if Mr_mip.ERNUM != 0 {
		return 0
	}
	MR_IN(98)

	if epoint_norm(p) == 0 { /* not possible ! */
		Mr_mip.depth--
		return (-1)
	}

	redc(p.X, x)
	redc(p.Y, Mr_mip.w1)

	if x != y {
		copy(Mr_mip.w1, y)
	}
	lsb = remain(Mr_mip.w1, 2)
	Mr_mip.depth--
	return lsb
}

//func mputs(s *uint8){
//	var i int =0
//	for s[i]!=0{
//		fmt.Printf(int(s[i++]))  //源码 while (s[i]!=0) fputc((int)s[i++],stdout);
//	}
//}

func mr_berror(nerr int) { /*  Big number error routine  */
	//var i int
	if Mr_mip.ERCON != 0 {
		Mr_mip.ERNUM = nerr
		return
	}
	fmt.Print(nerr)
	//mputs(*uint8("\nMIRACL error from routine "))
	//if Mr_mip.depth<24 {
	//	mputs(names[Mr_mip- > trace[Mr_mip- > depth]]);
	//}else{                           mputs(*uint8("???"))}
	//fmt.Println("")
	//
	//for i=Mr_mip.depth-1;i>=0;i-- {
	//	mputs((char *)
	//	"              called from ")
	//	if i < 24 {mputs(names[Mr_mip.trace[i]]
	//}else{               mputs((char *)"???")}
	//fputc('\n',stdout)
	//}
	//
	//switch (nerr)
	//{
	//case 1 :
	//mputs((char *)"Number base too big for representation\n");
	//break;
	//case 2 :
	//mputs((char *)"Division by zero attempted\n");
	//break;
	//case 3 :
	//mputs((char *)"Overflow - Number too big\n");
	//break;
	//case 4 :
	//mputs((char *)"Internal result is negative\n");
	//break;
	//case 5 :
	//mputs((char *)"Input format error\n");
	//break;
	//case 6 :
	//mputs((char *)"Illegal number base\n");
	//break;
	//case 7 :
	//mputs((char *)"Illegal parameter usage\n");
	//break;
	//case 8 :
	//mputs((char *)"Out of space\n");
	//break;
	//case 9 :
	//mputs((char *)"Even root of a negative number\n");
	//break;
	//case 10:
	//mputs((char *)"Raising integer to negative power\n");
	//break;
	//case 11:
	//mputs((char *)"Attempt to take illegal root\n");
	//break;
	//case 12:
	//mputs((char *)"Integer operation attempted on Flash number\n");
	//break;
	//case 13:
	//mputs((char *)"Flash overflow\n");
	//break;
	//case 14:
	//mputs((char *)"Numbers too big\n");
	//break;
	//case 15:
	//mputs((char *)"Log of a non-positive number\n");
	//break;
	//case 16:
	//mputs((char *)"Flash to double conversion failure\n");
	//break;
	//case 17:
	//mputs((char *)"I/O buffer overflow\n");
	//break;
	//case 18:
	//mputs((char *)"MIRACL not initialised - no call to mirsys()\n");
	//break;
	//case 19:
	//mputs((char *)"Illegal modulus \n");
	//break;
	//case 20:
	//mputs((char *)"No modulus defined\n");
	//break;
	//case 21:
	//mputs((char *)"Exponent too big\n");
	//break;
	//case 22:
	//mputs((char *)"Unsupported Feature - check mirdef.h\n");
	//break;
	//case 23:
	//mputs((char *)"Specified double length type isn't double length\n");
	//break;
	//case 24:
	//mputs((char *)"Specified basis is NOT irreducible\n");
	//break;
	//case 25:
	//mputs((char *)"Unable to control Floating-point rounding\n");
	//break;
	//case 26:
	//mputs((char *)"Base must be binary (MR_ALWAYS_BINARY defined in mirdef.h ?)\n");
	//break;
	//case 27:
	//mputs((char *)"No irreducible basis defined\n");
	//break;
	//case 28:
	//mputs((char *)"Composite modulus\n");
	//break;
	//case 29:
	//mputs((char *)"Input/output error when reading from RNG device node\n");
	//break;
	//default:
	//mputs((char *)"Undefined error\n");
	//break;
	//}
	//exit(0)
	//#else
	//mputs((char *)"MIRACL error\n")
	//exit(0)
	//
}

func muldiv(a uint32, b uint32, c uint32, m uint32, rp *uint32) uint32 {
	var q uint32
	var p uint64 = uint64(a*b + c) //unsigned long long这里是否转成uint64？
	q = uint32(p / uint64(m))
	*rp = uint32(p - uint64(q*m))
	return q
}

func muldvm(a uint32,c uint32,m uint32,rp *uint32)uint32 {
	var q uint32
	var dble doubleword
	a = uint32(int32(a))
	c = uint32(int32(c))
	m = uint32(int32(m))
	dble.h[0] = c
	dble.h[1] = a
	//dble.d = uint64(a)<<32 + uint64(c)
	dble.setDFromH()
	q = uint32(dble.d / uint64(m))
	*rp = uint32(dble.d - uint64(q*m))
	return q
}


//func muldvm222(a int32,c int32,m int32,rp *uint32)int32 {
//	var q int32
//	var dble doubleword
//	dble.h[0] = uint32(c)
//	dble.h[1] = uint32(a)
//	//dble.d = uint64(a)<<32 + uint64(c)
//	dble.setDFromH()
//	q = int32(dble.d / uint64(m))
//	*rp = uint32(dble.d - uint64(q*m))
//	return q
//}

func muldvd(a uint32,b uint32,c uint32,rp *uint32) uint32 {
	//var dble doubleword

	var d uint64 = uint64(a)*uint64(b)+uint64(c)
	var borrow uint32 = 0
	borrow = uint32(d/(1<<32))
	//if d >= 4294967296{
	//	borrow =d/
	//}
	*rp = uint32(d%(1<<32))
	//dble.d = uint64()
	//dble.h[1]=uint32(dble.d>>32)
	//dble.h[0]=uint32(dble.d)
	//*rp = uint32(int32(d))
	return borrow
}
func muldvd2(a uint32,b uint32,c *uint32,rp *uint32){
	var dble doubleword
	//dble.d=uint64(a*b+*c+*rp)
	dble.d=uint64(a)*uint64(b)+uint64(*c)+uint64(*rp)
	dble.h[1]=uint32(dble.d>>32)
	dble.h[0]=uint32(dble.d)
	*rp=dble.h[0]
	*c=dble.h[1]
}
//func muldvd2(a uint32,b uint32,c *uint32,rp *uint32){
//
//	var d uint64 =uint64(a)*uint64(b)+uint64(*c)+uint64(*rp)
//	*rp=uint32(d/(1<<32))
//	*c=uint32(d%(1<<32))
//}
//func muldvd(a uint32,b uint32,c uint32,rp *uint32)uint32 {
//	var dble doubleword
//	a = uint32(int32(a))
//	c = uint32(int32(c))
//	b = uint32(int32(b))
//
//	dble.d = uint64(a*b+c)
//	dble.h[1]=uint32(dble.d>>32)
//	dble.h[0]=uint32(dble.d)
//	*rp = dble.h[0]
//	return dble.h[1]
//}

func epoint_copy(a, b *Epoint) {
	if a == b || b == nil {
		return
	}

	copy(a.X, b.X)
	copy(a.Y, b.Y)

	if a.marker == 0 {
		copy(a.Z, b.Z)
	}

	b.marker = a.marker
	return
}

func epoint_negate(p *Epoint) { /* negate a point */
	if Mr_mip.ERNUM != 0 {
		return
	}
	if p.marker == 2 {
		return
	}
	MR_IN(121)
	if size(p.Y) != 0 {
		mr_psub(Mr_mip.modulus, p.Y, p.Y)
	}
	Mr_mip.depth--
}

//func memalloc(num int)*void {
//	return mr_alloc(mr_big_reserve(num, Mr_mip.nib-1), 1) //#define mr_big_reserve(n,m) ((n)*mr_size(m)+MR_SL)
//}
//
//func ecp_memalloc(num int)*void {
//	if Mr_mip.coord == 1 {
//		return mr_alloc(mr_ecp_reserve_a(num, Mr_mip.nib-1), 1) //#define mr_ecp_reserve_a(n,m) ((n)*mr_esize_a(m)+MR_SL)
//	} else {
//		return mr_alloc(mr_ecp_reserve(num, Mr_mip.nib-1), 1)
//	}
//}

func epoint_init_mem_variable(mem *uint8, index int, sz int) *Epoint {
	var p *Epoint=&Epoint{2,&Bigtype{0,[]uint32{}},&Bigtype{0,[]uint32{}},&Bigtype{0,[]uint32{}}}
	//var ptr *uint8
	//var offset, r int
	//
	//offset = 0
	//r = (unsignedlong)
	//mem % sizeof(long)
	//if r > 0 {
	//	offset = sizeof(long) - r
	//}
	//
	//if Mr_mip.coord == 1 {
	//	p = *Epoint(&mem[offset+index*mr_esize_a(sz)])
	//} else {
	//	p = *Epoint(&mem[offset+index*mr_esize(sz)])
	//}
	//
	//ptr = *uint8(p) + sizeof(epoint)
	//p.X = mirvar_mem_variable(ptr, 0, sz)
	//p.Y = mirvar_mem_variable(ptr, 1, sz)
	//
	//if Mr_mip.coord != 1 {
	//	p.Z = mirvar_mem_variable(ptr, 2, sz)
	//}
	//
	//p.marker = 2
	return p
}

func epoint_init_mem(mem *uint8, index int) *Epoint {
	if Mr_mip.ERNUM != 0 {
		return nil
	}
	return epoint_init_mem_variable(mem, index, Mr_mip.nib-1)
}

func ecurve_double(p *Epoint) { /* double epoint on active ecurve */
	if Mr_mip.ERNUM != 0 {
		return
	}
	if p.marker == 2 { /* 2 times infinity == infinity ! */
		return
	}
	if Mr_mip.coord == 1 { /* 2 sqrs, 1 mul, 1 div */
		if size(p.Y) == 0 { /* set to point at infinity */
			Epoint_set(nil, nil, 0, p)
			return
		}
		nres_modmult(p.X, p.X, Mr_mip.w8)     /* w8=x^2   */
		nres_premult(Mr_mip.w8, 3, Mr_mip.w8) /* w8=3*x^2 */
		if mr_abs(Mr_mip.Asize) == 1<<30 {
			nres_modadd(Mr_mip.w8, Mr_mip.A, Mr_mip.w8)
		} else {
			convert(Mr_mip.Asize, Mr_mip.w2)
			nres(Mr_mip.w2, Mr_mip.w2)
			nres_modadd(Mr_mip.w8, Mr_mip.w2, Mr_mip.w8)
		} /* w8=3*x^2+A */
		nres_premult(p.Y, 2, Mr_mip.w6) /* w6=2y */
		if nres_moddiv(Mr_mip.w8, Mr_mip.w6, Mr_mip.w8) > 1 {
			Epoint_set(nil, nil, 0, p)
			mr_berror(28)
			return
		}
		/* w8 is slope m on exit */
		nres_modmult(Mr_mip.w8, Mr_mip.w8, Mr_mip.w2) /* w2=m^2 */
		nres_premult(p.X, 2, Mr_mip.w1)
		nres_modsub(Mr_mip.w2, Mr_mip.w1, Mr_mip.w1) /* w1=m^2-2x */

		nres_modsub(p.X, Mr_mip.w1, Mr_mip.w2)
		nres_modmult(Mr_mip.w2, Mr_mip.w8, Mr_mip.w2)
		nres_modsub(Mr_mip.w2, p.Y, p.Y)
		copy(Mr_mip.w1, p.X)
		return
	}

	if size(p.Y) == 0 { /* set to point at infinity */
		Epoint_set(nil, nil, 0, p)
		return
	}

	convert(1, Mr_mip.w1)
	if mr_abs(Mr_mip.Asize) < 1<<30 {
		if Mr_mip.Asize != 0 {
			if p.marker == 1 {
				nres(Mr_mip.w1, Mr_mip.w6)
			} else {
				nres_modmult(p.Z, p.Z, Mr_mip.w6)
			}
		}
		if Mr_mip.Asize == (-3) { /* a is -3. Goody. 4 sqrs, 4 muls */
			nres_modsub(p.X, Mr_mip.w6, Mr_mip.w3)
			nres_modadd(p.X, Mr_mip.w6, Mr_mip.w8)
			nres_modmult(Mr_mip.w3, Mr_mip.w8, Mr_mip.w3)
			nres_modadd(Mr_mip.w3, Mr_mip.w3, Mr_mip.w8)
			nres_modadd(Mr_mip.w8, Mr_mip.w3, Mr_mip.w8)
		} else { /* a is small */
			if Mr_mip.Asize != 0 { /* a is non zero! */
				nres_modmult(Mr_mip.w6, Mr_mip.w6, Mr_mip.w3)
				nres_premult(Mr_mip.w3, Mr_mip.Asize, Mr_mip.w3)
			}
			nres_modmult(p.X, p.X, Mr_mip.w1)
			nres_modadd(Mr_mip.w1, Mr_mip.w1, Mr_mip.w8)
			nres_modadd(Mr_mip.w8, Mr_mip.w1, Mr_mip.w8)
			if Mr_mip.Asize != 0 {
				nres_modadd(Mr_mip.w8, Mr_mip.w3, Mr_mip.w8)
			}
		}
	} else { /* a is not special */
		if p.marker == 1 {
			nres(Mr_mip.w1, Mr_mip.w6)
		} else {
			nres_modmult(p.Z, p.Z, Mr_mip.w6)
		}

		nres_modmult(Mr_mip.w6, Mr_mip.w6, Mr_mip.w3)
		nres_modmult(Mr_mip.w3, Mr_mip.A, Mr_mip.w3)
		nres_modmult(p.X, p.X, Mr_mip.w1)
		nres_modadd(Mr_mip.w1, Mr_mip.w1, Mr_mip.w8)
		nres_modadd(Mr_mip.w8, Mr_mip.w1, Mr_mip.w8)
		nres_modadd(Mr_mip.w8, Mr_mip.w3, Mr_mip.w8)
	}

	/* w8 contains numerator of slope 3x^2+A.z^4  *
	* denominator is now placed in Z             */

	nres_modmult(p.Y, p.Y, Mr_mip.w2)
	nres_modmult(p.X, Mr_mip.w2, Mr_mip.w3)
	nres_modadd(Mr_mip.w3, Mr_mip.w3, Mr_mip.w3)
	nres_modadd(Mr_mip.w3, Mr_mip.w3, Mr_mip.w3)
	nres_modmult(Mr_mip.w8, Mr_mip.w8, p.X)
	nres_modsub(p.X, Mr_mip.w3, p.X)
	nres_modsub(p.X, Mr_mip.w3, p.X)

	if p.marker == 1 {
		copy(p.Y, p.Z)
	} else {
		nres_modmult(p.Z, p.Y, p.Z)
	}
	nres_modadd(p.Z, p.Z, p.Z)

	nres_modadd(Mr_mip.w2, Mr_mip.w2, Mr_mip.w7)
	nres_modmult(Mr_mip.w7, Mr_mip.w7, Mr_mip.w2)
	nres_modadd(Mr_mip.w2, Mr_mip.w2, Mr_mip.w2)
	nres_modsub(Mr_mip.w3, p.X, Mr_mip.w3)
	nres_modmult(Mr_mip.w8, Mr_mip.w3, p.Y)
	nres_modsub(p.Y, Mr_mip.w2, p.Y)

	p.marker = 0
	return
}

func ecurve_padd(p, pa *Epoint) int {
	/* primitive add two epoints on the active ecurve - pa+=p;   *
	* note that if p is normalized, its Z coordinate isn't used */

	if Mr_mip.coord == 1 { /* 1 sqr, 1 mul, 1 div */

		nres_modsub(p.Y, pa.Y, Mr_mip.w8)
		nres_modsub(p.X, pa.X, Mr_mip.w6)
		if size(Mr_mip.w6) == 0 { /* divide by 0 */
			if size(Mr_mip.w8) == 0 { /* should have doubled ! */
				return 0
			} else { /* point at infinity */
				Epoint_set(nil, nil, 0, pa)
				return 1
			}
		}
		if nres_moddiv(Mr_mip.w8, Mr_mip.w6, Mr_mip.w8) > 1 {
			Epoint_set(nil, nil, 0, pa)
			mr_berror(28)
			return 1
		}

		nres_modmult(Mr_mip.w8, Mr_mip.w8, Mr_mip.w2) /* w2=m^2 */
		nres_modsub(Mr_mip.w2, p.X, Mr_mip.w1)        /* w1=m^2-x1-x2 */
		nres_modsub(Mr_mip.w1, pa.X, Mr_mip.w1)

		nres_modsub(pa.X, Mr_mip.w1, Mr_mip.w2)
		nres_modmult(Mr_mip.w2, Mr_mip.w8, Mr_mip.w2)
		nres_modsub(Mr_mip.w2, pa.Y, pa.Y)
		copy(Mr_mip.w1, pa.X)

		pa.marker = 1
		return 1

	}

	if p.marker != 1 {
		nres_modmult(p.Z, p.Z, Mr_mip.w6)
		nres_modmult(pa.X, Mr_mip.w6, Mr_mip.w1)
		nres_modmult(Mr_mip.w6, p.Z, Mr_mip.w6)
		nres_modmult(pa.Y, Mr_mip.w6, Mr_mip.w8)
	} else {
		copy(pa.X, Mr_mip.w1)
		copy(pa.Y, Mr_mip.w8)
	}
	if pa.marker == 1 {
		copy(Mr_mip.one, Mr_mip.w6)
	} else {
		nres_modmult(pa.Z, pa.Z, Mr_mip.w6)
	}

	nres_modmult(p.X, Mr_mip.w6, Mr_mip.w4)
	if pa.marker != 1 {
		nres_modmult(Mr_mip.w6, pa.Z, Mr_mip.w6)
	}
	nres_modmult(p.Y, Mr_mip.w6, Mr_mip.w5)
	nres_modsub(Mr_mip.w1, Mr_mip.w4, Mr_mip.w1)
	nres_modsub(Mr_mip.w8, Mr_mip.w5, Mr_mip.w8)

	/* w8 contains the numerator of the slope */

	if size(Mr_mip.w1) == 0 {
		if size(Mr_mip.w8) == 0 { /* should have doubled ! */
			return 0
		} else { /* point at infinity */
			Epoint_set(nil, nil, 0, pa)
			return 1
		}
	}
	nres_modadd(Mr_mip.w4, Mr_mip.w4, Mr_mip.w6)
	nres_modadd(Mr_mip.w1, Mr_mip.w6, Mr_mip.w4)
	nres_modadd(Mr_mip.w5, Mr_mip.w5, Mr_mip.w6)
	nres_modadd(Mr_mip.w8, Mr_mip.w6, Mr_mip.w5)

	if p.marker != 1 {
		if pa.marker != 1 {
			nres_modmult(pa.Z, p.Z, Mr_mip.w3)
		} else {
			copy(p.Z, Mr_mip.w3)
		}
		nres_modmult(Mr_mip.w3, Mr_mip.w1, pa.Z)
	} else {
		if pa.marker != 1 {
			nres_modmult(pa.Z, Mr_mip.w1, pa.Z)
		} else {
			copy(Mr_mip.w1, pa.Z)
		}
	}
	nres_modmult(Mr_mip.w1, Mr_mip.w1, Mr_mip.w6)
	nres_modmult(Mr_mip.w1, Mr_mip.w6, Mr_mip.w1)
	nres_modmult(Mr_mip.w6, Mr_mip.w4, Mr_mip.w6)
	nres_modmult(Mr_mip.w8, Mr_mip.w8, Mr_mip.w4)

	nres_modsub(Mr_mip.w4, Mr_mip.w6, pa.X)
	nres_modsub(Mr_mip.w6, pa.X, Mr_mip.w6)
	nres_modsub(Mr_mip.w6, pa.X, Mr_mip.w6)
	nres_modmult(Mr_mip.w8, Mr_mip.w6, Mr_mip.w2)
	nres_modmult(Mr_mip.w1, Mr_mip.w5, Mr_mip.w1)
	nres_modsub(Mr_mip.w2, Mr_mip.w1, Mr_mip.w5)

	/* divide by 2 */

	nres_div2(Mr_mip.w5, pa.Y)

	pa.marker = 0
	return 1

}

func nres_div2(x, w Big) {
	MR_IN(198)
	copy(x, Mr_mip.w1)
	if remain(Mr_mip.w1, 2) != 0 {
		Add(Mr_mip.w1, Mr_mip.modulus, Mr_mip.w1)
	}
	subdiv(Mr_mip.w1, 2, Mr_mip.w1)
	copy(Mr_mip.w1, w)
	Mr_mip.depth--
}

func ecurve_add(p, pa *Epoint) int { /* pa=pa+p; */

	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(94)

	if p == pa {
		ecurve_double(pa)
		Mr_mip.depth--
		if pa.marker == 2 {
			return 0
		}
		return 2
	}
	if pa.marker == 2 {
		epoint_copy(p, pa)
		Mr_mip.depth--
		return 1
	}
	if p.marker == 2 {
		Mr_mip.depth--
		return 1
	}

	if ecurve_padd(p, pa) == 0 {
		ecurve_double(pa)
		Mr_mip.depth--
		return 2
	}
	Mr_mip.depth--
	if pa.marker == 2 {
		return 0
	}
	return 1
}

func nres_multi_inverse(m int, x []Big, w []Big) int { /* find w[i]=1/x[i] mod n, for i=0 to m-1 *
	* x and w MUST be distinct               */
	var i int
	if m == 0 {
		return 1
	}
	if m < 0 {
		return 2
	}
	MR_IN(118)
	if reflect.DeepEqual(x, w) {

		mr_berror(7)
		Mr_mip.depth--
		return 0
	}

	if m == 1 {
		copy(Mr_mip.one, w[0])
		nres_moddiv(w[0], x[0], w[0])
		Mr_mip.depth--
		return 1
	}

	convert(1, w[0])
	copy(x[0], w[1])
	for i = 2; i < m; i++ {
		nres_modmult(w[i-1], x[i-1], w[i])
	}

	nres_modmult(w[m-1], x[m-1], Mr_mip.w6) /* y=x[0]*x[1]*x[2]....x[m-1] */
	if size(Mr_mip.w6) == 0 {
		mr_berror(2)
		Mr_mip.depth--
		return 0
	}

	redc(Mr_mip.w6, Mr_mip.w6)
	redc(Mr_mip.w6, Mr_mip.w6)

	invmodp(Mr_mip.w6, Mr_mip.modulus, Mr_mip.w6)

	/* Now y=1/y */

	copy(x[m-1], Mr_mip.w5)
	nres_modmult(w[m-1], Mr_mip.w6, w[m-1])

	for i = m - 2; ; i-- {
		if i == 0 {
			nres_modmult(Mr_mip.w5, Mr_mip.w6, w[0])
			break
		}
		nres_modmult(w[i], Mr_mip.w5, w[i])
		nres_modmult(w[i], Mr_mip.w6, w[i])
		nres_modmult(Mr_mip.w5, x[i], Mr_mip.w5)
	}

	Mr_mip.depth--
	return 1
}

func epoint_multi_norm(m int, work []Big, p []*Epoint) int { /* Normalise an array of points of length m<MR_MAX_M_T_S - requires a workspace array of length m */
	var i, inf int
	inf = 0
	var w [64]Big
	if Mr_mip.coord == 1 {
		return 1
	}
	if Mr_mip.ERNUM != 0 {
		return 0
	}
	if m > 64 {
		return 0
	}

	MR_IN(190)

	for i = 0; i < m; i++ {
		if p[i].marker == 1 {
			w[i] = Mr_mip.one
		} else {
			w[i] = p[i].Z
		}
		if p[i].marker == 2 {
			inf = 1
			break
		} /* whoops, one of them is point at infinity */
	}

	if inf != 0 {
		for i = 0; i < m; i++ {
			epoint_norm(p[i])
		}
		Mr_mip.depth--
		return 1
	}

	if nres_multi_inverse(m, w[0:], work) == 0 {
		Mr_mip.depth--
		return 0
	}

	for i = 0; i < m; i++ {
		copy(Mr_mip.one, p[i].Z)
		p[i].marker = 1
		nres_modmult(work[i], work[i], Mr_mip.w1)
		nres_modmult(p[i].X, Mr_mip.w1, p[i].X) /* X/ZZ */
		nres_modmult(Mr_mip.w1, work[i], Mr_mip.w1)
		nres_modmult(p[i].Y, Mr_mip.w1, p[i].Y) /* Y/ZZZ */
	}
	Mr_mip.depth--

	return 1
}

func ecurve_sub(p, pa *Epoint) int {
	var r int

	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(104)

	if p == pa {
		Epoint_set(nil, nil, 0, pa)
		Mr_mip.depth--
		return 0
	}
	if p.marker == 2 {
		Mr_mip.depth--
		return 1
	}

	epoint_negate(p)
	r = ecurve_add(p, pa)
	epoint_negate(p)

	Mr_mip.depth--
	return r
}

func mr_naf_window(x Big, x3 Big, i int, nbs *int, nzs *int, store int) int {
	var nb, j, r, biggest int

	/* get first bit */
	nb = mr_testbit(x3, i) - mr_testbit(x, i)

	*nbs = 1
	*nzs = 0
	if nb == 0 {
		return 0
	}
	if i == 0 {
		return nb
	}

	biggest = 2*store - 1

	if nb > 0 {
		r = 1
	} else {
		r = (-1)
	}

	for j = i - 1; j > 0; j-- {
		(*nbs)++
		r *= 2
		nb = mr_testbit(x3, j) - mr_testbit(x, j)
		if nb > 0 {
			r += 1
		}
		if nb < 0 {
			r -= 1
		}
		if r > biggest || -r > biggest {
			break
		}
	}

	if r%2 != 0 && j != 0 { /* backtrack */
		if nb > 0 {
			r = (r - 1) / 2
		}
		if nb < 0 {
			r = (r + 1) / 2
		}
		(*nbs)--
	}

	for r%2 == 0 { /* remove trailing zeros */
		r /= 2
		(*nzs)++
		(*nbs)--
	}
	return r
}

//func mreflect

func memkill(mem *uint8, len int) {
	if mem == nil {
		return
	}
	//memset(mem, 0, mr_big_reserve(len, Mr_mip.nib-1))
	//mr_free(mem)
}

func ecp_memkill(mem *uint8, num int) {
	if mem == nil {
		return
	}
	//if Mr_mip.coord == 1 {
	//	memset(mem, 0, mr_ecp_reserve_a(num, Mr_mip.nib-1)) //#define mr_ecp_reserve_a(n,m) ((n)*mr_esize_a(m)+MR_SL)
	//} else { //memset也是stblib的库函数
	//	memset(mem, 0, mr_ecp_reserve(num, Mr_mip.nib-1))
	//}
	//mr_free(mem)
}

func ecurve_mult(e Big, pa *Epoint, pt *Epoint) int { /* pt=e*pa; */
	var i, j, n, nb, nbs, nzs, nadds int
	var table [8]*Epoint
	var work [8]Big
	var mem *uint8
	var mem1 *uint8
	var p *Epoint
	var ce, ch int
	if Mr_mip.ERNUM != 0 {
		return 0
	}

	MR_IN(95)
	if size(e) == 0 { /* multiplied by 0 */
		Epoint_set(nil, nil, 0, pt)
		Mr_mip.depth--
		return 0
	}
	copy(e, Mr_mip.w9)
	//epoint_norm(pa)
	epoint_copy(pa, pt)

	if size(Mr_mip.w9) < 0 { /* pt = -pt */
		negify(Mr_mip.w9, Mr_mip.w9)
		epoint_negate(pt)
	}

	if size(Mr_mip.w9) == 1 {
		Mr_mip.depth--
		return 0
	}

	premult(Mr_mip.w9, 3, Mr_mip.w10) /* h=3*e */

	if Mr_mip.base == Mr_mip.base2 {

		//mem = *uint8(ecp_memalloc(8))
		//
		//mem1 = *uint8(memalloc(8))

		for i = 0; i <= 7; i++ {
			table[i] = epoint_init_mem(mem, i)
			work[i] = mirvar_mem(mem1, i)
		}

		epoint_copy(pt, table[0])
		epoint_copy(table[0], table[7])
		ecurve_double(table[7])
		/*   epoint_norm(table[MR_ECC_STORE_N-1]); */

		for i = 1; i < 7; i++ { /* precomputation */
			epoint_copy(table[i-1], table[i])
			ecurve_add(table[7], table[i])
		}
		ecurve_add(table[6], table[7])

		epoint_multi_norm(8, work[0:], table[0:])

		nb = logb2(Mr_mip.w10)
		nadds = 0
		Epoint_set(nil, nil, 0, pt)
		for i = nb - 1; i >= 1; { /* add/subtract */
			//if Mr_mip.user != nil {
			//	*Mr_mip.user()
			//}
			n = mr_naf_window(Mr_mip.w9, Mr_mip.w10, i, &nbs, &nzs, 8)
			for j = 0; j < nbs; j++ {
				ecurve_double(pt)
			}
			if n > 0 {
				ecurve_add(table[n/2], pt)
				nadds++
			}
			if n < 0 {
				ecurve_sub(table[(-n)/2], pt)
				nadds++
			}
			i -= nbs
			if nzs != 0 {
				for j = 0; j < nzs; j++ {
					ecurve_double(pt)
				}
				i -= nzs
			}
		}

		ecp_memkill(mem, 8)

		memkill(mem1, 8)

	} else {
		//mem = *uint8(ecp_memalloc(1))
		p = epoint_init_mem(mem, 0)
		epoint_norm(pt)
		epoint_copy(pt, p)

		nadds = 0
		expb2(logb2(Mr_mip.w10)-1, Mr_mip.w11)
		mr_psub(Mr_mip.w10, Mr_mip.w11, Mr_mip.w10)
		subdiv(Mr_mip.w11, 2, Mr_mip.w11)
		for size(Mr_mip.w11) > 1 { /* add/subtract method */
			//if Mr_mip.user != nil {
			//	*Mr_mip.user()
			//}

			ecurve_double(pt)
			ce = mr_compare(Mr_mip.w9, Mr_mip.w11)  /* e(i)=1? */
			ch = mr_compare(Mr_mip.w10, Mr_mip.w11) /* h(i)=1? */
			if ch >= 0 {                            /* h(i)=1 */
				if ce < 0 {
					ecurve_add(p, pt)
					nadds++
				}
				mr_psub(Mr_mip.w10, Mr_mip.w11, Mr_mip.w10)
			}
			if ce >= 0 { /* e(i)=1 */
				if ch < 0 {
					ecurve_sub(p, pt)
					nadds++
				}
				mr_psub(Mr_mip.w9, Mr_mip.w11, Mr_mip.w9)
			}
			subdiv(Mr_mip.w11, 2, Mr_mip.w11)
		}
		ecp_memkill(mem, 1)
	}

	Mr_mip.depth--
	return nadds
}

func Mirsys(nd int, nb uint32) *Miracl {
	Mr_mip = mr_first_alloc()
	Mr_mip = get_mip()
	return mirsys_basic(Mr_mip, nd, nb)
}

func mr_first_alloc() *Miracl {
	return &Miracl{}
	//return *Miracl(calloc(1, sizeof(miracl)))
}

func get_mip() *Miracl {
	//return *Miracl(Mr_mip)
	return &Miracl{}
}

func mr_setbase(nb uint32) uint32 { /* set base. Pack as many digits as  *
	* possible into each computer word  */
	var temp uint32

	var fits, bits int

	fits = 0
	bits = 32
	for bits > 1 {
		bits /= 2
		temp = uint32(1 << uint32(bits))
		if temp == nb {
			fits = 1
			break
		}
		if temp < nb || (bits%2) != 0 {
			break
		}
	}
	if fits != 0 {
		Mr_mip.apbase = nb
		Mr_mip.pack = 32 / bits
		Mr_mip.base = 0
		return 0
	}
	Mr_mip.apbase = nb
	Mr_mip.pack = 1
	Mr_mip.base = nb
	if Mr_mip.base == 0 {
		return 0
	}
	temp = (1 << 31) / nb
	for temp >= nb {
		temp = temp / nb
		Mr_mip.base *= nb
		Mr_mip.pack++
	}
	return 0
}

func mirsys_basic(Mr_mip *Miracl, nd int, nb uint32) *Miracl {
	var i int
	var nw, b uint32

	if Mr_mip == nil {
		return nil
	}
	Mr_mip.depth = 0
	Mr_mip.trace[0] = 0
	Mr_mip.depth++
	Mr_mip.trace[Mr_mip.depth] = 29

	Mr_mip.ERCON = 0

	Mr_mip.logN = 0
	Mr_mip.degree = 0
	Mr_mip.chin.NP = 0
	Mr_mip.user = nil
	Mr_mip.same = 0
	Mr_mip.first_one = 0
	Mr_mip.debug = 0
	Mr_mip.AA = 0

	Mr_mip.coord = 0

	//if (sizeof(_int64) < 2*sizeof(int)) { /* double length type, isn't */
	//	mr_berror(23)
	//	Mr_mip.depth--
	//	return Mr_mip
	//}

	if nb == 1 || nb > 1<<31 {
		mr_berror(6)
		Mr_mip.depth--
		return Mr_mip
	}

	mr_setbase(nb)
	b = Mr_mip.base

	Mr_mip.lg2b = 0
	Mr_mip.base2 = 1

	if b == 0 {

		Mr_mip.lg2b = 32
		Mr_mip.base2 = 0
	} else {
		for b > 1 {
			b = b / 2
			Mr_mip.lg2b++
			Mr_mip.base2 *= 2
		}
	}

	if nd > 0 {
		nw = uint32((nd-1)/Mr_mip.pack + 1)
	} else {
		nw = uint32((8*(-nd)-1)/Mr_mip.lg2b + 1)
	}

	if nw < 1 {
		nw = 1
	}
	Mr_mip.nib = (int)(nw + 1) /* add one extra word for small overflows */

	Mr_mip.workprec = Mr_mip.nib
	Mr_mip.stprec = Mr_mip.nib
	for Mr_mip.stprec > 2 && Mr_mip.stprec > 52/Mr_mip.lg2b {
		Mr_mip.stprec = (Mr_mip.stprec + 1) / 2
	}
	if Mr_mip.stprec < 2 {
		Mr_mip.stprec = 2
	}

	Mr_mip.check = 1

	Mr_mip.IOBASE = 10 /* defaults */

	Mr_mip.ERNUM = 0

	Mr_mip.NTRY = 6
	Mr_mip.MONTY = 1

	Mr_mip.EXACT = 1
	Mr_mip.RPOINT = 0

	Mr_mip.TRACER = 0

	Mr_mip.INPLEN = 0
	Mr_mip.IOBSIZ = 1024

	Mr_mip.PRIMES = nil
	//Mr_mip.IOBUFF = *uint8(mr_alloc(1025, 1))
	//Mr_mip.IOBUFF[0] ='\0'

	Mr_mip.qnr = 0
	Mr_mip.cnr = 0
	Mr_mip.TWIST = 0
	Mr_mip.pmod8 = 0
	Mr_mip.pmod9 = 0

	Mr_mip.ira[0] = 0x55555555
	Mr_mip.ira[1] = 0x12345678

	for i = 2; i < 37; i++ {
		Mr_mip.ira[i] = Mr_mip.ira[i-1] + Mr_mip.ira[i-2] + 0x1379BDF1
	}
	Mr_mip.rndptr = 37
	Mr_mip.borrow = 0

	Mr_mip.nib = 2*Mr_mip.nib + 1

	if Mr_mip.nib != (Mr_mip.nib & (0xffff)) {
		mr_berror(14)
		Mr_mip.nib = (Mr_mip.nib - 1) / 2
		Mr_mip.depth--
		return Mr_mip
	}

	//Mr_mip.workspace = *uint8(memalloc(28)) /* grab workspace */

	Mr_mip.M = 0
	Mr_mip.fin = 0
	Mr_mip.fout = 0
	Mr_mip.active = 1

	Mr_mip.nib = (Mr_mip.nib - 1) / 2

	Mr_mip.w0 = mirvar_mem(Mr_mip.workspace, 0) /* double length */
	Mr_mip.w1 = mirvar_mem(Mr_mip.workspace, 2)
	Mr_mip.w2 = mirvar_mem(Mr_mip.workspace, 3)
	Mr_mip.w3 = mirvar_mem(Mr_mip.workspace, 4)
	Mr_mip.w4 = mirvar_mem(Mr_mip.workspace, 5)
	Mr_mip.w5 = mirvar_mem(Mr_mip.workspace, 6)  /* double length */
	Mr_mip.w6 = mirvar_mem(Mr_mip.workspace, 8)  /* double length */
	Mr_mip.w7 = mirvar_mem(Mr_mip.workspace, 10) /* double length */
	Mr_mip.w8 = mirvar_mem(Mr_mip.workspace, 12)
	Mr_mip.w9 = mirvar_mem(Mr_mip.workspace, 13)
	Mr_mip.w10 = mirvar_mem(Mr_mip.workspace, 14)
	Mr_mip.w11 = mirvar_mem(Mr_mip.workspace, 15)
	Mr_mip.w12 = mirvar_mem(Mr_mip.workspace, 16)
	Mr_mip.w13 = mirvar_mem(Mr_mip.workspace, 17)
	Mr_mip.w14 = mirvar_mem(Mr_mip.workspace, 18)
	Mr_mip.w15 = mirvar_mem(Mr_mip.workspace, 19)
	Mr_mip.sru = mirvar_mem(Mr_mip.workspace, 20)
	Mr_mip.modulus = mirvar_mem(Mr_mip.workspace, 21)
	Mr_mip.pR = mirvar_mem(Mr_mip.workspace, 22) /* double length */
	Mr_mip.A = mirvar_mem(Mr_mip.workspace, 24)
	Mr_mip.B = mirvar_mem(Mr_mip.workspace, 25)
	Mr_mip.one = mirvar_mem(Mr_mip.workspace, 26)

	Mr_mip.pi = mirvar_mem(Mr_mip.workspace, 27)

	Mr_mip.depth--
	return Mr_mip
}
