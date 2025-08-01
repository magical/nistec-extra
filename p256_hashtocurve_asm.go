//go:build !purego && (amd64 || arm64 || (ppc64le && go1.19) || s390x)

package nistec

import (
	"errors"
)

// RFC9380
//
// Section 6.6.2 Simplified Shallue-van de Woestijne-Ulas Method

func P256MapToCurve(bytes []byte) (*P256Point, error) {
	var p P256Point
	return p256MapToCurve(&p, bytes)
}

func p256MapToCurve(p *P256Point, bytes []byte) (*P256Point, error) {
	if len(bytes) != 32 {
		return nil, errors.New("invalid P256 element encoding")
	}
	u := new(p256Element)
	p256BigToLittle(u, (*[32]byte)(bytes[0:32]))
	if p256LessThanP(u) == 0 {
		return nil, errors.New("invalid P256 element encoding")
	}
	sgn0u := int(bytes[len(bytes)-1] & 1)

	// Convert u to montgomery domain
	rr := &p256Element{0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd}
	p256Mul(u, u, rr)

	// Steps:
	// t1 = Z^2 * u^4 + Z * u^2
	//   1.  tv1 = u^2
	//   2.  tv1 = Z * tv1
	//   3.  tv2 = tv1^2
	//   4.  tv2 = tv2 + tv1

	Z := &p256Element{0xfffffffffffffff5, 0xaffffffff, 0x0, 0xfffffff50000000b}
	Zu2 := new(p256Element)
	t0 := new(p256Element)
	p256Sqr(t0, u, 1)
	p256Mul(Zu2, Z, t0)
	t1 := new(p256Element)
	p256Sqr(t0, Zu2, 1)
	p256Add(t1, Zu2, t0)

	// x1 = -B/A * (1 + t1) / t1  if t1 != 0
	//       B/A *        1 / Z   if t1 == 0
	//
	//   5.  tv3 = tv2 + 1
	//   6.  tv3 = B * tv3
	//   7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	//   8.  tv4 = A * tv4

	x1 := new(p256Element)
	p256Add(x1, t1, &p256One)
	isZero := p256Equal(t1, &p256Zero)
	p256NegCond(x1, isZero)
	BoverA := &p256Element{0x9d899fcb6341949f, 0x8efaac9a7d816585, 0xa1e0b58ea7b5ba47, 0xf410020901826d67}
	p256Mul(x1, x1, BoverA)

	x1d := new(p256Element)
	if isZero == 1 { // TODO constant time
		//fmt.Printf("tv1 is zero (u=%x)\n", bytes)
		*x1d = *Z
	} else {
		*x1d = *t1
	}

	//   25.   x1 = x1 / x1d
	//p256Inverse(x1d, x1d)
	//p256Mul(x1, x1, x1d)
	//*x1d = p256One

	// 4. gx1 = x1^3 + A * x1 x1d^2 + B x1d^3
	// and gd = x1d^3
	gx1 := new(p256Element)
	p256Sqr(gx1, x1, 1)
	p256Mul(gx1, gx1, x1)

	p256Sqr(t0, x1d, 1)
	gd := new(p256Element)
	p256Mul(gd, t0, x1d)
	// t1 = -3*x1 xd^2
	p256Mul(t1, t0, x1)
	p256Add(t0, t1, t1)
	p256Add(t0, t0, t1)
	p256NegCond(t0, 1)
	p256Add(gx1, gx1, t0)

	B := &p256Element{0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834}
	p256Mul(t0, gd, B)
	p256Add(gx1, gx1, t0)

	// 5.  x2 = Z * u^2 * x1
	x2 := new(p256Element)
	p256Mul(x2, Zu2, x1)

	// 6. (y1, isSquare) = sqrt(gx1)
	y1 := new(p256Element)
	isSquare := p256SqrtRatio(y1, gx1, gd)

	// Through some sort of freaky magic,
	// it turns out that if x1 is not square then
	// x2=Z*u^2*x1 will be, AND we can obtain
	// its square root by multiplying our failed square
	// root by -Z^(3/2)*u^3.
	y2 := new(p256Element)
	p256Mul(y2, Zu2, u)
	sqrtNegZ := &p256Element{0xa1fd38ee98a195fd, 0x78400ad7423dcf70, 0x6913c88f9ea8dfee, 0x9051d26e12a8f304}
	p256Mul(y2, y2, sqrtNegZ)
	p256Mul(y2, y2, y1)

	//   21.   x = CMOV(x, x1, is_gx1_square)
	//   22.   y = CMOV(y, y1, is_gx1_square)
	x := new(p256Element)
	y := new(p256Element)
	if isSquare == 1 {
		// TODO: constant time
		*x = *x1
		*y = *y1
	} else {
		//fmt.Printf("isn't square (u=%x)\n", bytes)
		*x = *x2
		*y = *y2
	}

	// If sgn0(u) != sgn0(y), set y = -y
	cond := sgn0u ^ sgn0(y)
	p256NegCond(y, cond)

	//p256Inverse(x1d, x1d)
	//p256Mul(x, x, x1d)

	// convert to affine coordinates
	p256Mul(x, x, x1d)
	p256Mul(y, y, gd) // y = y * x1d^3

	// 10. return (x, y)
	p.x = *x
	p.y = *y
	p.z = *x1d
	return p, nil
}

func sgn0(y *p256Element) int {
	y0 := new(p256Element)
	p256FromMont(y0, y)
	return int(y0[0] & 1)
}

// mysqrt sets z to a candidate square root of (u/v)
// and returns 1 if (u/v) is a square and 0 if not.
func p256SqrtRatio(z, u, v *p256Element) (isSquare int) {
	// this is pretty clever!
	// normally we can calculate the square root of an element x
	// by raising x^((p+1)/4)
	// which works for number theory reasons, and because p=3 mod 4
	//
	// we could use that to find sqrt(u/v) by calculating x=u/v
	// but there's a shortcut that doesn't require inverting v:
	// instead of doing x^((p+1)/4), stop short at x^((p+1)/4 - 1) = x^((p-3)/4)
	// which calculates the reciprocal square root, x^(-1/2)
	// and instead of using x=u/v use x=uv^3
	// so we get (uv^3)^(-1/2) = u^(-1/2) v^(-3/2)
	// and then multiply that by uv to get
	// u^(1/2) v^(-1/2) = (u/v)^(1/2)
	// poof!
	// sqrt(u/v) without any inversions
	//
	//
	// x = uv*v^2
	uv := new(p256Element)
	p256Mul(uv, u, v)
	x := new(p256Element)
	p256Sqr(x, v, 1)
	p256Mul(x, uv, x)

	// z = x^((p-3)/4)
	// as it turns out, this is the same as the chain for inversion
	// but without the last couple multiplies
	t0 := new(p256Element)
	t1 := new(p256Element)
	p256Sqr(z, x, 1)     // double  z       x
	p256Mul(z, x, z)     // add     z       x       z
	p256Sqr(z, z, 1)     // double  z       z
	p256Mul(z, x, z)     // add     z       x       z
	p256Sqr(t0, z, 3)    // shift   t0      z       3
	p256Mul(t0, z, t0)   // add     t0      z       t0
	p256Sqr(t1, t0, 6)   // shift   t1      t0      6
	p256Mul(t0, t0, t1)  // add     t0      t0      t1
	p256Sqr(t0, t0, 3)   // shift   t0      t0      3
	p256Mul(z, z, t0)    // add     z       z       t0
	p256Sqr(t0, z, 1)    // double  t0      z
	p256Mul(t0, x, t0)   // add     t0      x       t0
	p256Sqr(t1, t0, 16)  // shift   t1      t0      16
	p256Mul(t0, t0, t1)  // add     t0      t0      t1
	p256Sqr(t0, t0, 15)  // shift   t0      t0      15
	p256Mul(z, z, t0)    // add     z       z       t0
	p256Sqr(t0, t0, 17)  // shift   t0      t0      17
	p256Mul(t0, x, t0)   // add     t0      x       t0
	p256Sqr(t0, t0, 143) // shift   t0      t0      143
	p256Mul(t0, z, t0)   // add     t0      z       t0
	p256Sqr(t0, t0, 47)  // shift   t0      t0      47
	p256Mul(z, z, t0)    // add     z       z       t0

	// z = z*uv
	p256Mul(z, z, uv)

	// now check that it's actually the root
	// (u == z^2 * v)
	p256Sqr(t0, z, 1)
	p256Mul(t0, t0, v)
	return p256Equal(t0, u)
}
