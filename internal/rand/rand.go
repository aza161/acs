package rand

import (
	"crypto/rand"
	"math/big"
)

// returns an cryptographically secure random int in [min, max].
func GetRand(min, max int64) int {
	minBig, maxBig := big.NewInt(min), big.NewInt(max+1)
	randMax := new(big.Int).Sub(maxBig, minBig)

	randNum, err := rand.Int(rand.Reader, randMax)

	if err != nil {
		panic(err)
	}

	randNum.Add(randNum, minBig)

	return int(randNum.Int64())
}
