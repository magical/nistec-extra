//go:build purego || (!amd64 && !arm64 && !(ppc64le && go1.19) && !s390x)

package nistec

import "filippo.io/nistec/internal/fiat"

// RFC9380
//
// Section 6.6.2 Simplified Shallue-van de Woestijne-Ulas Method

func P256MapToCurve(bytes []byte) (*P256Point, error) {
	u, err := new(fiat.P256Element).SetBytes(bytes)
	if err != nil {
		return nil, err
	}
	sgn0u := bytes[len(bytes)-1] & 1
	zero := new(fiat.P256Element)
	one := new(fiat.P256Element).One()
	B := p256B()

	// A = -3
	A := new(fiat.P256Element)
	for i := 0; i < 3; i++ {
		A.Sub(A, one)
	}
	// Z = -10
	Z := new(fiat.P256Element)
	for i := 0; i < 10; i++ {
		Z.Sub(Z, one)
	}

	// Precompute -B/A and B/ZA
	// TODO: cache these
	t0 := new(fiat.P256Element) // temporary
	negBoverA := new(fiat.P256Element).Mul(
		new(fiat.P256Element).Sub(zero, B),
		new(fiat.P256Element).Invert(A),
	)
	ZA := new(fiat.P256Element).Mul(Z, A)
	BoverZA := new(fiat.P256Element).Mul(B, t0.Invert(ZA))

	// 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
	Zu2 := new(fiat.P256Element).Mul(Z, t0.Square(u))
	tv1 := new(fiat.P256Element).Add(Zu2, t0.Square(Zu2))
	tv1.Invert(tv1)
	// 2.  x1 = (-B / A) * (1 + tv1)
	x1 := new(fiat.P256Element).Add(one, tv1)
	x1.Mul(x1, negBoverA)
	// 3.  If tv1 == 0, set x1 = B / (Z * A)
	x1.Select(BoverZA, x1, tv1.IsZero())
	// 4. gx1 = x1^3 + A * x1 + B
	gx1 := new(fiat.P256Element)
	p256Polynomial(gx1, x1)
	// 5.  x2 = Z * u^2 * x1
	x2 := new(fiat.P256Element).Mul(Zu2, x1)
	// 6. gx2 = x2^3 + A * x2 + B
	gx2 := new(fiat.P256Element)
	p256Polynomial(gx2, x2)
	// 7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
	// 8.  Else set x = x2 and y = sqrt(gx2)
	c0 := new(fiat.P256Element)
	c1 := new(fiat.P256Element)
	p256SqrtCandidate(c0, gx1)
	p256SqrtCandidate(c1, gx2)
	isSquare := gx1.Equal(t0.Square(c0))
	x := new(fiat.P256Element).Select(x1, x2, isSquare)
	y := new(fiat.P256Element).Select(c0, c1, isSquare)
	// 9.  If sgn0(u) != sgn0(y), set y = -y
	yNeg := new(fiat.P256Element).Sub(zero, y)
	yBytes := y.Bytes()
	sgn0y := yBytes[len(yBytes)-1] & 1
	y = y.Select(yNeg, y, int(sgn0u^sgn0y))
	// 10. return (x, y)
	return &P256Point{x, y, one}, nil
}

// mysqrt sets e to a candidate square root of x
// and returns 1 if x is a square and 0 if not.
func mysqrt(e, x *fiat.P256Element) (isSquare int) {
	p256SqrtCandidate(e, x)
	square := new(fiat.P256Element).Square(e)
	return square.Equal(x)
}

// Section 3. Encoding Byte Strings to Elliptic Curves

// hash_to_curve(msg)
//
// Input: msg, an arbitrary-length byte string.
// Output: P, a point in G.
//
// Steps:
// 1. u = hash_to_field(msg, 2)
// 2. Q0 = map_to_curve(u[0])
// 3. Q1 = map_to_curve(u[1])
// 4. R = Q0 + Q1              # Point addition
// 5. P = clear_cofactor(R)
// 6. return P

func HashToCurve(bytes []byte) (*P256Point, error) {
	var u0 []byte
	var u1 []byte
	//u0 := fiat.NewP256Element().SetBytes(u0)
	q0, err := P256MapToCurve(u0)
	if err != nil {
		return nil, err
	}
	q1, err := P256MapToCurve(u1)
	if err != nil {
		return nil, err
	}
	p := NewP256Point().Add(q0, q1)
	// The cofactor of P-256 is 1, so we don't need to clear it
	return p, nil
}

func GetX(p *P256Point) []byte { return p.x.Bytes() }
func GetY(p *P256Point) []byte { return p.y.Bytes() }
