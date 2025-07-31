//go:build !purego && (amd64 || arm64 || (ppc64le && go1.19) || s390x)

package nistec

import "errors"

// RFC9380
//
// Section 6.6.2 Simplified Shallue-van de Woestijne-Ulas Method

func P256MapToCurve(bytes []byte) (*P256Point, error) {
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

	B := &p256Element{0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834}
	one := &p256One
	negOne := new(p256Element)
	*negOne = *one
	p256NegCond(negOne, 1)

	// A = -3
	A := new(p256Element)
	for i := 0; i < 3; i++ {
		p256Add(A, A, negOne)
	}
	// Z = -10
	Z := new(p256Element)
	for i := 0; i < 10; i++ {
		p256Add(Z, Z, negOne)
	}

	// Precompute -B/A and B/ZA
	// TODO: cache these
	t0 := new(p256Element)
	negBoverA := new(p256Element)
	p256Inverse(t0, A)
	p256NegCond(t0, 1)
	p256Mul(negBoverA, B, t0)
	ZA := new(p256Element)
	p256Mul(ZA, Z, A)
	BoverZA := new(p256Element)
	p256Inverse(t0, ZA)
	p256Mul(BoverZA, B, t0)

	// 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
	Zu2 := new(p256Element)
	p256Sqr(t0, u, 1)
	p256Mul(Zu2, Z, t0)
	tv1 := new(p256Element)
	p256Sqr(t0, Zu2, 1)
	p256Add(tv1, Zu2, t0)
	p256Inverse(tv1, tv1)
	// 2.  x1 = (-B / A) * (1 + tv1)
	x1 := new(p256Element)
	p256Add(x1, one, tv1)
	p256Mul(x1, x1, negBoverA)
	// 3.  If tv1 == 0, set x1 = B / (Z * A)
	if p256Equal(tv1, &p256Zero) == 1 { // TODO: constant time
		*x1 = *BoverZA
	}
	// 4. gx1 = x1^3 + A * x1 + B
	gx1 := new(p256Element)
	p256Polynomial(gx1, x1)
	// 5.  x2 = Z * u^2 * x1
	x2 := new(p256Element)
	p256Mul(x2, Zu2, x1)
	// 6. gx2 = x2^3 + A * x2 + B
	gx2 := new(p256Element)
	p256Polynomial(gx2, x2)
	// 7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
	// 8.  Else set x = x2 and y = sqrt(gx2)
	c1 := new(p256Element)
	c2 := new(p256Element)
	isSquare := mysqrt(c1, gx1)
	mysqrt(c2, gx2)
	var x, y = x2, c2
	if isSquare == 1 { // TODO: constant time
		x = x1
		y = c1
	}
	// 9.  If sgn0(u) != sgn0(y), set y = -y
	cond := sgn0u ^ sgn0(y)
	p256NegCond(y, cond)
	// 10. return (x, y)
	return &P256Point{*x, *y, *one}, nil
}

func sgn0(y *p256Element) int {
	y0 := new(p256Element)
	p256FromMont(y0, y)
	return int(y0[0] & 1)
}

// mysqrt sets e to a candidate square root of x
// and returns 1 if x is a square and 0 if not.
func mysqrt(e, x *p256Element) (isSquare int) {
	if p256Sqrt(e, x) {
		return 1
	}
	return 0
}
