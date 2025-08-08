// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build purego || (!amd64 && !arm64 && !(ppc64le && go1.19) && !s390x)

package nistec

import "github.com/magical/nistec-extra/internal/fiat"

// Negate sets p = -q and returns p.
func (p *P256Point) Negate(q *P256Point) *P256Point {
	p.x.Set(q.x)
	p.y.Sub(new(fiat.P256Element), q.y)
	p.z.Set(q.z)
	return p
}

// IsZero returns 1 if p is the identity point, otherwise 0.
func (p *P256Point) IsZero() int {
	return p.z.IsZero()
}
