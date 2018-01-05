package authsrv

import (
	"github.com/chemikadze/gorberos/datamodel"
	"fmt"
)

type RevocationHotlist interface {
	Revoke(startTime datamodel.KerberosTime, endTime datamodel.KerberosTime)
	IsRevoked(startTime datamodel.KerberosTime) bool
}

/** Revocation time interval */
type revocation struct {
	from datamodel.KerberosTime
	to datamodel.KerberosTime
}

func (r revocation) String() string {
	return fmt.Sprintf("{from:%v, to:%v}", r.from, r.to)
}

func (r revocation) Equal(other revocation) bool {
	return r.from.Equal(other.from) && r.to.Equal(other.to)
}

func (r revocation) Intersects(other revocation) bool {
	return r.from.ToUnix() <= other.to.ToUnix() && r.to.ToUnix() >= other.from.ToUnix()
}

func (r revocation) Contains(point datamodel.KerberosTime) bool {
	return r.from.ToUnix() <= point.ToUnix() && point.ToUnix() <= r.to.ToUnix()
}

func (r revocation) ToLeftOf(other revocation) bool {
	return r.to.ToUnix() < other.from.ToUnix()
}

func (r revocation) ToRightOf(other revocation) bool {
	return r.from.ToUnix() > other.to.ToUnix()
}

func (r revocation) Merge(other revocation) revocation {
	if !r.Intersects(other) {
		panic(fmt.Sprintf("Can't merge non-intersecting ranges %v and %v", r, other))
	}
	return revocation{
		from: r.from.Min(other.from),
		to: r.to.Max(other.to),
	}
}

/** Revocation hotlist implementation

Based on range-centric suggestion from 3.3.3.1. of rfc4120
 */
type revocationHotlist struct {
	revocations []revocation
	maxLifetime int64
}

func NewRevocationHotlist(maxLifetime int64) RevocationHotlist {
	hotlist := revocationHotlist{
		revocations: make([]revocation, 0),
		maxLifetime: maxLifetime,
	}
	return &hotlist
}

func (r *revocationHotlist) Revoke(startTime datamodel.KerberosTime, endTime datamodel.KerberosTime) {
	if startTime.ToUnix() > endTime.ToUnix() {
		panic(fmt.Sprintf("startTime %v for revoked timestamp > endTime %v", startTime, endTime))
	}
	inserted := revocation{from: startTime, to:endTime}
	if len(r.revocations) == 0 || r.revocations[len(r.revocations)-1].to.ToUnix() < inserted.from.ToUnix() {
		r.revocations = append(r.revocations, inserted)
	} else if inserted.to.ToUnix() < r.revocations[0].from.ToUnix() {
		r.revocations = append(append(make([]revocation, 0), inserted), r.revocations...)
	} else {
		for i, curr := range r.revocations {
			// intersects with current
			if inserted.Intersects(curr) {
				updated := inserted.Merge(curr)
				r.revocations[i] = updated
				for i < len(r.revocations)-1 && r.revocations[i].Intersects(r.revocations[i+1]) {
					updated = r.revocations[i].Merge(r.revocations[i+1])
					head := r.revocations[:max(0, i)]
					tail := r.revocations[i+2:]
					r.revocations = append(append(head, updated), tail...)
				}
				break
			}
			// in between
			if i < len(r.revocations)-1 {
				next := r.revocations[i+1]
				if curr.ToLeftOf(inserted) && inserted.ToLeftOf(next) {
					head := r.revocations[:i]
					tail := r.revocations[i:]
					r.revocations = append(append(head, inserted), tail...)
					break
				}
			}
		}
	}
	r.cleanup()
	r.save()
}

func (r *revocationHotlist) IsRevoked(startTime datamodel.KerberosTime) bool {
	for _, curr := range r.revocations {
		if curr.Contains(startTime) {
			return true
		}
	}
	return false
}

func (r *revocationHotlist) cleanup() {
	revocationPoint := datamodel.KerberosTimeNow().Minus(r.maxLifetime)
	// nothing to clean
	if len(r.revocations) == 0 {
		return
	}
	// all valid
	if revocationPoint.ToUnix() < r.revocations[0].from.ToUnix() {
		return
	}
	// all invalid
	if r.revocations[len(r.revocations)-1].to.ToUnix() < revocationPoint.ToUnix() {
		r.revocations = make([]revocation, 0)
	}
	// locate invalid prefix and drop
	for i := 1; i < len(r.revocations); i++ {
		curr := r.revocations[i]
		prev := r.revocations[i-1]
		if prev.to.ToUnix() < revocationPoint.ToUnix() && curr.to.ToUnix() >= revocationPoint.ToUnix() {
			retained := make([]revocation, len(r.revocations) - i)
			copy(retained, r.revocations[i:])
			r.revocations = retained
			return
		}
	}
	// nothing changed
	return
}

func (r *revocationHotlist) save() {
	// TODO noop
}

func max(a, b int) int {
	if a > b {
		return a
	} else {
		return b
	}
}

