package passutils

import (
	"acs/internal/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/go-passwd/validator"
	"github.com/sethvargo/go-diceware/diceware"
	"github.com/sethvargo/go-password/password"
	passwordvalidator "github.com/wagslane/go-password-validator"
)

// Ensure that minDigiSymbol <= minPasswordLen/maxFactor
// recommeded min value for minPasswordLen is 16
const (
	minDigiSymbol    int64 = 3
	minPasswordLen   int64 = 16
	maxPasswordLen   int64 = 128
	maxFactor        int64 = 5
	minPassphraseLen int64 = 7
)

// Generates cryptographically secure random parameters necessary for MustGenerate.
func getPassGenParameters() (int, int, int) {
	passLen := rand.GetRand(minPasswordLen, maxPasswordLen)

	// Determines the symbols+digits to alphabets ratio
	ratioFactor := rand.GetRand(2, maxFactor)

	maxDigiSymbol := int64(passLen / ratioFactor)

	totalDigiSymbol := int64(rand.GetRand(minDigiSymbol, maxDigiSymbol))

	// Determines the symbols to digits ratio
	symbolFactor := rand.GetRand(2, totalDigiSymbol-1)

	totalSymbol := totalDigiSymbol / int64(symbolFactor)

	totalDigi := totalDigiSymbol - totalSymbol

	// Add extra randomness by switching the digits and symbols
	extraRand := rand.GetRand(0, 1)

	if extraRand%2 == 0 {
		temp := totalDigi
		totalDigi = totalSymbol
		totalSymbol = temp
	}

	return passLen, int(totalDigi), int(totalSymbol)
}

// Generates a custom password generator to be used if the user wants to use custom symbols.
func getGenerator(symbols string) *password.Generator {
	gen, err := password.NewGenerator(&password.GeneratorInput{
		Symbols: symbols,
	})
	if err != nil {
		panic(err)
	}
	return gen
}

// Generates a cryptographically secure random password.
func GeneratePassword(customSymbols string, noUpper bool) string {
	gen := getGenerator(customSymbols)
	passLen, digits, symbols := getPassGenParameters()
	return gen.MustGenerate(passLen, digits, symbols, noUpper, true)
}

// Validates the security of a password and measures its entropy.
// A user can pass a set of custom symbols to check if the password contains minNumSymbols of them.
func CheckPasswordStrength(pass string, userInfo []string, symbols *string, minNumSymbols int) error {
	sim := 0.3
	passwordValidator := validator.New(
		validator.MinLength(int(minPasswordLen), nil),
		validator.MaxLength(int(maxPasswordLen), nil),
		validator.CommonPassword(nil),
		validator.ContainsAtLeast(*symbols+password.Digits, int(minDigiSymbol), nil),
		validator.ContainsAtLeast(*symbols, minNumSymbols, nil),
		validator.Similarity(userInfo, &sim, nil),
	)
	err := passwordValidator.Validate(pass)
	if err == nil {
		entropy := passwordvalidator.GetEntropy(pass)
		if entropy < 80 {
			return errors.New("bad password becasue of low entropy, try making it more random")
		}
	}
	return err
}

// This function generates easy to remember passphrases for better user experience.
// It depends on the diceware library which contains around 7776 words in its dictionary.
// Each word has around 13 bits of entropy. Therefore to achieve at least 80 bits of
// entropy we need at least 7 words.
func GeneratePassphrase(length int) (string, error) {
	if length < int(minPassphraseLen) {
		return "", fmt.Errorf("passphrase length must be %d at least", minPassphraseLen)
	}
	passph := strings.Join(diceware.MustGenerate(length), "-")
	return passph, nil
}
