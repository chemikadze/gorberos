package authsrv

import (
	"testing"
	"github.com/chemikadze/gorberos/datamodel"
)

func createRevocation() *revocationHotlist {
	r := NewRevocationHotlist(3600)
	return r.(*revocationHotlist)
}

func TestHotlistCreation(t *testing.T) {
	var r RevocationHotlist = NewRevocationHotlist(3600)
	if r == nil {
		t.Error("Should not be nil")
	}
	if r.IsRevoked(datamodel.KerberosTimeNow()) {
		t.Error("Nothing should be revoked")
	}
}

func TestHotlistSimpleRevoke(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	t1 := now.Minus(10)
	t2 := now.Plus(10)
	r.Revoke(t1, t2)
	if !r.IsRevoked(now) {
		t.Error("Point inside interval should be revoked")
	}
	if !r.IsRevoked(t1) {
		t.Error("Starting point of interval should be revoked")
	}
	if !r.IsRevoked(t2) {
		t.Error("End point of interval should be revoked")
	}
	if r.IsRevoked(now.Minus(20)) {
		t.Error("Point before interval should not be revoked")
	}
	if r.IsRevoked(now.Plus(20)) {
		t.Error("Point after interval should not be revoked")
	}
}

func TestHotlistRevokeTwoIntervals(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	x1 := now.Minus(110)
	x2 := now.Minus(100)
	y1 := now.Minus(10)
	y2 := now.Minus(0)
	r.Revoke(x1, x2)
	r.Revoke(y1, y2)
	if !(r.IsRevoked(x1) && r.IsRevoked(x1.Plus(5)) && r.IsRevoked(x2)) {
		t.Error("First interval should be revoked")
	}
	if !(r.IsRevoked(y1) && r.IsRevoked(y1.Plus(5)) && r.IsRevoked(y2)) {
		t.Error("Second interval should be revoked")
	}
	if r.IsRevoked(x1.Minus(5)) || r.IsRevoked(x2.Plus(5)) || r.IsRevoked(y2.Plus(5)) {
		t.Error("Points before, between and after intervals should not be revoked")
	}
}

func TestHotlistRevocationExpiration(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	t1 := now.Minus(10000)
	t2 := now.Minus(9000)
	r.Revoke(t1, t2)
	if r.IsRevoked(t1) {
		t.Error("Revocations older than ticket expiration time should be removed")
	}
	x1 := now.Minus(4000)
	x2 := now
	r.Revoke(x1, x2)
	if !r.IsRevoked(x2) {
		t.Error("Revocations should not be removed until interval end won't expire")
	}
}

func TestHotlistIntersectingRevocationMerge(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	t1 := now.Minus(60)
	t2 := now.Minus(30)
	r.Revoke(t1, t2)
	x1 := now.Minus(45)
	x2 := now.Minus(15)
	r.Revoke(x1, x2)
	if len(r.revocations) != 1 {
		t.Errorf("Two revocations should merge to one, found %v instead", r.revocations)
	}
	expectedMerge := revocation{t1, x2}
	if r.revocations[0] != expectedMerge {
		t.Errorf("Expected proper merge %v, found %v", expectedMerge, r.revocations[0])
	}
}

func TestHotlistEnclosedRevocationMerge(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	t1 := now.Minus(60)
	t2 := now.Minus(15)
	r.Revoke(t1, t2)
	x1 := now.Minus(45)
	x2 := now.Minus(30)
	r.Revoke(x1, x2)
	if len(r.revocations) != 1 {
		t.Errorf("Two revocations should merge to one, found %v instead", r.revocations)
	}
	expectedMerge := revocation{t1, t2}
	if r.revocations[0] != expectedMerge {
		t.Errorf("Expected proper merge %v, found %v", expectedMerge, r.revocations[0])
	}
}

func TestHotlistBigMergeBeginning(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	a1 := now.Minus(100)
	a2 := now.Minus(90)
	r.Revoke(a1, a2)
	b1 := now.Minus(80)
	b2 := now.Minus(70)
	r.Revoke(b1, b2)
	c1 := now.Minus(60)
	c2 := now.Minus(50)
	r.Revoke(c1, c2)
	if len(r.revocations) != 3 {
		t.Errorf("Expected 3 distinct intervals, got %v", r.revocations)
	}
	x1 := a1.Plus(5)
	x2 := b1.Plus(5)
	r.Revoke(x1, x2)
	expectedMerge := revocation{a1, b2}
	if r.revocations[0] != expectedMerge {
		t.Errorf("Expected proper merge %v, found %v", expectedMerge, r.revocations[0])
	}
}

func TestHotlistBigMergeTail(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	a1 := now.Minus(100)
	a2 := now.Minus(90)
	r.Revoke(a1, a2)
	b1 := now.Minus(80)
	b2 := now.Minus(70)
	r.Revoke(b1, b2)
	c1 := now.Minus(60)
	c2 := now.Minus(50)
	r.Revoke(c1, c2)
	if len(r.revocations) != 3 {
		t.Errorf("Expected 3 distinct intervals, got %v", r.revocations)
	}
	x1 := b1.Plus(5)
	x2 := c1.Plus(5)
	r.Revoke(x1, x2)
	if len(r.revocations) != 2 {
		t.Errorf("Expected 2 distinct intervals after merge, got %v", r.revocations)
	}
	expectedMerge := revocation{b1, c2}
	if r.revocations[1] != expectedMerge {
		t.Errorf("Expected proper merge %v, found %v", expectedMerge, r.revocations[0])
	}
}

func TestHotlistBigMergeMulti(t *testing.T) {
	r := createRevocation()
	now := datamodel.KerberosTimeNow()
	beg1 := now.Minus(200)
	beg2 := now.Minus(190)
	r.Revoke(beg1, beg2)
	a1 := now.Minus(100)
	a2 := now.Minus(90)
	r.Revoke(a1, a2)
	b1 := now.Minus(80)
	b2 := now.Minus(70)
	r.Revoke(b1, b2)
	c1 := now.Minus(60)
	c2 := now.Minus(50)
	r.Revoke(c1, c2)
	end1 := now.Minus(10)
	end2 := now
	r.Revoke(end1, end2)
	if len(r.revocations) != 5 {
		t.Errorf("Expected 5 distinct intervals, got %v", r.revocations)
	}
	x1 := a1.Plus(5)
	x2 := c1.Plus(5)
	r.Revoke(x1, x2)
	if len(r.revocations) != 3 {
		t.Errorf("Expected 3 interval after merge, got %v", r.revocations)
	}
	expectedMerge := revocation{a1, c2}
	if r.revocations[1] != expectedMerge {
		t.Errorf("Expected proper merge %v, found %v", expectedMerge, r.revocations[0])
	}
	beg := revocation{beg1, beg2}
	end := revocation{end1, end2}
	if r.revocations[0] != beg {
		t.Errorf("First interval supposed to be untouched %v, got %v", beg, r.revocations[0])
	}
	if r.revocations[2] != end {
		t.Errorf("First interval supposed to be untouched %v, got %v", end, r.revocations[2])
	}
}

