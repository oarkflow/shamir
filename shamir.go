package shamir

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"sync"
)

// --- GF(256) arithmetic tables & operations --------------------------------

// Precomputed tables for GF(256) arithmetic using polynomial 0x11b
var (
	expTable [512]byte
	logTable [256]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		x = gfMulNoLUT(x, 0x03)
	}
	// duplicate to avoid mod operations
	for i := 255; i < 512; i++ {
		expTable[i] = expTable[i-255]
	}
}

// bitwise multiplication for table generation
func gfMulNoLUT(a, b byte) byte {
	var p byte
	for b > 0 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// Add and Sub are XOR
func add(a, b byte) byte { return a ^ b }
func sub(a, b byte) byte { return a ^ b }

// Multiply using exp/log tables
func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	s := int(logTable[a]) + int(logTable[b])
	if s >= 255 {
		s -= 255
	}
	return expTable[s]
}

// Inverse in GF(256)
func inv(a byte) (byte, error) {
	if a == 0 {
		return 0, errors.New("shamir: inverse of zero")
	}
	return expTable[255-int(logTable[a])], nil
}

// --- Constants, pools, interfaces ------------------------------------------

const (
	magicHeader = "SHAM" // 4 bytes
	version     = 1      // 1 byte
)

var (
	// pool for coefficient buffers to reduce allocations
	coeffPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 256)
			return &buf
		},
	}
)

// IStorage defines storage operations for shares.
type IStorage interface {
	SetShare(index byte, share []byte) error
	GetShare(index byte) ([]byte, error)
	ListShares() ([]byte, error)
	DeleteShare(index byte) error
	BatchSet(shares map[byte][]byte) error
}

// ShareJSON is the portable JSON form of a share.
type ShareJSON struct {
	Index       byte   `json:"index"`
	Threshold   byte   `json:"threshold"`
	TotalShares byte   `json:"total_shares"`
	Data        string `json:"data"` // base64-encoded payload
}

// --- Split & Combine -------------------------------------------------------

// Split splits the secret into n shares requiring t to reconstruct.
func Split(secret []byte, t, n int) ([][]byte, error) {
	return SplitWithReader(rand.Reader, secret, t, n)
}

// SplitWithReader allows custom RNG (for testing).
func SplitWithReader(rng io.Reader, secret []byte, t, n int) ([][]byte, error) {
	if t < 2 || t > 255 {
		return nil, errors.New("shamir: threshold must be between 2 and 255")
	}
	if n < t || n > 255 {
		return nil, errors.New("shamir: number of shares must be between threshold and 255")
	}
	secretLen := len(secret)
	// header = magic(4)+ver(1)+thr(1)+tot(1)+len(2)+idx(1)
	const headLen = 4 + 1 + 1 + 1 + 2 + 1

	shares := make([][]byte, n)
	for i := range shares {
		buf := make([]byte, headLen+secretLen+4) // +4 for CRC32
		copy(buf[0:], []byte(magicHeader))
		buf[4] = version
		buf[5] = byte(t)
		buf[6] = byte(n)
		binary.BigEndian.PutUint16(buf[7:], uint16(secretLen))
		buf[9] = byte(i + 1) // index from 1..n
		shares[i] = buf
	}

	// for each secret byte, build polynomial and evaluate
	for j := 0; j < secretLen; j++ {
		pb := coeffPool.Get().(*[]byte)
		coeffs := (*pb)[:t]
		coeffs[0] = secret[j]
		if _, err := io.ReadFull(rng, coeffs[1:]); err != nil {
			return nil, err
		}
		for i := 0; i < n; i++ {
			x := shares[i][9]
			var y byte = coeffs[0]
			var px byte = 1
			for k := 1; k < t; k++ {
				px = mul(px, x)
				y ^= mul(coeffs[k], px)
			}
			shares[i][headLen+j] = y
		}
		// zero out and return buffer
		for k := range coeffs {
			coeffs[k] = 0
		}
		coeffPool.Put(pb)
	}

	// append CRC32
	for _, buf := range shares {
		d := buf[:headLen+secretLen]
		crc := crc32.ChecksumIEEE(d)
		binary.BigEndian.PutUint32(buf[len(buf)-4:], crc)
	}

	return shares, nil
}

// Combine reconstructs the secret from exactly t shares.
func Combine(shares [][]byte) ([]byte, error) {
	t := len(shares)
	if t < 2 {
		return nil, errors.New("shamir: need at least 2 shares")
	}

	// parse header of first share
	h := shares[0]
	if len(h) < 10 {
		return nil, errors.New("shamir: invalid share length")
	}
	if string(h[0:4]) != magicHeader {
		return nil, errors.New("shamir: bad magic header")
	}
	if h[4] != version {
		return nil, errors.New("shamir: version mismatch")
	}
	threshold := int(h[5])
	total := h[6]
	secretLen := int(binary.BigEndian.Uint16(h[7:9]))
	const headLen = 4 + 1 + 1 + 1 + 2 + 1

	// Modified check: accept at least threshold shares.
	if t < threshold {
		return nil, errors.New("shamir: insufficient shares provided")
	} else if t > threshold {
		// Use first threshold shares if more provided.
		shares = shares[:threshold]
		t = threshold
	}

	xs := make([]byte, t)
	data := make([][]byte, t)
	seen := make(map[byte]bool, t)

	for i, buf := range shares {
		if len(buf) != headLen+secretLen+4 {
			return nil, errors.New("shamir: share length mismatch")
		}
		// CRC check
		end := len(buf)
		expected := binary.BigEndian.Uint32(buf[end-4:])
		if crc32.ChecksumIEEE(buf[:end-4]) != expected {
			return nil, errors.New("shamir: CRC32 mismatch")
		}
		if buf[5] != byte(threshold) || buf[6] != total {
			return nil, errors.New("shamir: inconsistent header fields")
		}
		x := buf[9]
		if x == 0 || seen[x] {
			return nil, errors.New("shamir: invalid or duplicate index")
		}
		seen[x] = true
		xs[i] = x
		data[i] = buf[headLen : headLen+secretLen]
	}

	// compute Lagrange weights
	prodAll := byte(1)
	for _, x := range xs {
		prodAll = mul(prodAll, x)
	}
	lags := make([]byte, t)
	for i := 0; i < t; i++ {
		d := byte(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			d = mul(d, xs[i]^xs[j])
		}
		i1, _ := inv(xs[i])
		d1, _ := inv(d)
		lags[i] = mul(mul(prodAll, i1), d1)
	}

	// reconstruct secret
	secret := make([]byte, secretLen)
	for j := 0; j < secretLen; j++ {
		var v byte
		for i := 0; i < t; i++ {
			v ^= mul(data[i][j], lags[i])
		}
		secret[j] = v
	}
	return secret, nil
}

// --- Storage helpers -------------------------------------------------------

// StoreShares saves all shares to the given storage.
func StoreShares(shares [][]byte, st IStorage) error {
	batch := make(map[byte][]byte, len(shares))
	for _, s := range shares {
		batch[s[9]] = s
	}
	return st.BatchSet(batch)
}

// RetrieveShares fetches specific shares by indices.
func RetrieveShares(indices []byte, st IStorage) ([][]byte, error) {
	var out [][]byte
	for _, idx := range indices {
		s, err := st.GetShare(idx)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// MultiPartyAuthorize retrieves and combines shares for quorum.
func MultiPartyAuthorize(st IStorage, indices []byte, threshold int) ([]byte, error) {
	shs, err := RetrieveShares(indices, st)
	if err != nil {
		return nil, err
	}
	if len(shs) < threshold {
		return nil, errors.New("shamir: insufficient shares for threshold")
	}
	return Combine(shs[:threshold])
}

// BreakGlassRecovery uses a separate set of recovery shares.
func BreakGlassRecovery(st IStorage, indices []byte, threshold int) ([]byte, error) {
	return MultiPartyAuthorize(st, indices, threshold)
}

// --- Serialization ---------------------------------------------------------

// EncodeBase64 returns a base64 string of a raw share.
func EncodeBase64(share []byte) string {
	return base64.StdEncoding.EncodeToString(share)
}

// DecodeBase64 parses a base64 share.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeHex returns a hex string of a raw share.
func EncodeHex(share []byte) string {
	return hex.EncodeToString(share)
}

// DecodeHex parses a hex-encoded share.
func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// ToJSON converts a share into JSON form.
func ToJSON(share []byte) (string, error) {
	if len(share) < 10 {
		return "", errors.New("shamir: invalid share")
	}
	thr := share[5]
	tot := share[6]
	idx := share[9]
	body := share[9 : len(share)-4]
	j := ShareJSON{
		Index:       idx,
		Threshold:   thr,
		TotalShares: tot,
		Data:        base64.StdEncoding.EncodeToString(body),
	}
	b, err := json.Marshal(j)
	return string(b), err
}

// FromJSON parses JSON back into a raw share.
func FromJSON(js string) ([]byte, error) {
	var j ShareJSON
	if err := json.Unmarshal([]byte(js), &j); err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(j.Data)
	if err != nil {
		return nil, err
	}
	secretLen := len(data)
	const headLen = 4 + 1 + 1 + 1 + 2 + 1
	buf := make([]byte, headLen+secretLen+4)
	copy(buf[0:], []byte(magicHeader))
	buf[4] = version
	buf[5] = j.Threshold
	buf[6] = j.TotalShares
	binary.BigEndian.PutUint16(buf[7:], uint16(secretLen))
	buf[9] = j.Index
	copy(buf[10:], data)
	crc := crc32.ChecksumIEEE(buf[:len(buf)-4])
	binary.BigEndian.PutUint32(buf[len(buf)-4:], crc)
	return buf, nil
}
