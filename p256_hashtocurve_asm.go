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

	Z := &p256Element{0xfffffffffffffff5, 0xaffffffff, 0x0, 0xfffffff50000000b}
	negBoverA := &p256Element{0x9d899fcb6341949f, 0x8efaac9a7d816585, 0xa1e0b58ea7b5ba47, 0xf410020901826d67}
	BoverZA := &p256Element{0x5c8dc32df0535ba9, 0xc17f77a98c8cf08d, 0x7696788e43f892a0, 0x9868003399c03e24}

	t0 := new(p256Element) // temporary

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
	p256Add(x1, &p256One, tv1)
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
	p.x = *x
	p.y = *y
	p.z = p256One
	return p, nil
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
