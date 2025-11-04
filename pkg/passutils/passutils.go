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
	"golang.org/x/crypto/argon2"
)

// password length / digits / symbols defaults
const (
	minDigiSymbol    int64 = 3
	minPasswordLen   int64 = 16
	maxPasswordLen   int64 = 128
	maxFactor        int64 = 5
	minPassphraseLen int64 = 7
)

const (
	Time    uint32 = 1
	Memory  uint32 = 64 * 1024
	Threads uint8  = 8
	SaltLen uint32 = 16 // in bytes
	KeyLen  uint32 = 32 // in bytes
)

var (
	ShortSalt  error = errors.New("salt should be 16 bytes at least")
	NoPassword error = errors.New("password empty")
	NoThreads  error = errors.New("threads should be >=1 ")
)

// random params for password generation
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

// custom generator with user symbols
func getGenerator(symbols string) *password.Generator {
	gen, err := password.NewGenerator(&password.GeneratorInput{
		Symbols: symbols,
	})
	if err != nil {
		panic(err)
	}
	return gen
}

// GeneratePassword returns a crypto-strong password.
func GeneratePassword(customSymbols string, noUpper bool) string {
	gen := getGenerator(customSymbols)
	passLen, digits, symbols := getPassGenParameters()
	return gen.MustGenerate(passLen, digits, symbols, noUpper, true)
}

// CheckPasswordStrength validates password strength.
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

// GeneratePassphrase returns a diceware passphrase (>=7 words).
func GeneratePassphrase(length int) (string, error) {
	if length < int(minPassphraseLen) {
		return "", fmt.Errorf("passphrase length must be %d at least", minPassphraseLen)
	}
	passph := strings.Join(diceware.MustGenerate(length), "-")
	return passph, nil
}

func Argon2ID(pass string, salt []byte, threads uint8) ([]byte, error) {
	if len(pass) == 0 {
		return nil, NoPassword
	}

	if threads == 0 {
		return nil, NoThreads
	}

	if len(salt) != int(SaltLen) {
		return nil, ShortSalt
	}

	key := argon2.IDKey([]byte(pass), salt, Time, Memory, threads, KeyLen)
	return key, nil
}

// PassphraseOptions defines how to customize a diceware-style passphrase.
type PassphraseOptions struct {
	Length           int    // number of words
	Separator        string // e.g. "-", "_", " ", ""
	RandomSeparator  bool   // if true, pick random separators from SeparatorSet
	SeparatorSet     string // e.g. "-_." used only if RandomSeparator=true
	AddNumber        bool   // add a digit somewhere
	AddSymbol        bool   // add a symbol somewhere
	NumberPosition   string // "prefix", "suffix", "between"
	SymbolPosition   string // "prefix", "suffix", "between"
	SymbolSet        string // custom symbol set, default: "!@#$%^&*"
	CaseStyle        string // "none", "title", "random"
	MinWordsRequired int    // safety lower bound, e.g. 7
}

func GeneratePassphraseAdvanced(opts PassphraseOptions) (string, error) {
	if opts.Length == 0 {
		opts.Length = int(minPassphraseLen)
	}
	if opts.MinWordsRequired == 0 {
		opts.MinWordsRequired = int(minPassphraseLen)
	}
	if opts.Length < opts.MinWordsRequired {
		return "", fmt.Errorf("passphrase length must be %d at least", opts.MinWordsRequired)
	}
	if opts.Separator == "" {
		opts.Separator = "-"
	}
	if opts.SymbolSet == "" {
		opts.SymbolSet = "!@#$%^&*"
	}
	if opts.SeparatorSet == "" {
		opts.SeparatorSet = "-_." // tiny default pool
	}
	if opts.CaseStyle == "" {
		opts.CaseStyle = "none"
	}

	words := diceware.MustGenerate(opts.Length)

	for i := range words {
		switch opts.CaseStyle {
		case "title":
			words[i] = strings.Title(words[i])
		case "random":
			if rand.GetRand(0, 1) == 1 {
				words[i] = strings.Title(words[i])
			}
		default:
		}
	}

	var passph string
	if opts.RandomSeparator {
		var b strings.Builder
		for i, w := range words {
			b.WriteString(w)
			if i < len(words)-1 {
				idx := rand.GetRand(0, int64(len(opts.SeparatorSet))-1)
				sep := opts.SeparatorSet[idx : idx+1]
				b.WriteString(sep)
			}
		}
		passph = b.String()
	} else {
		passph = strings.Join(words, opts.Separator)
	}

	// helper to insert in-between words (i.e. inside the string)
	insertBetween := func(base, insert string) string {
		pos := rand.GetRand(0, int64(len(base)))
		return base[:pos] + insert + base[pos:]
	}

	if opts.AddNumber {
		d := fmt.Sprintf("%d", rand.GetRand(0, 9))
		switch opts.NumberPosition {
		case "prefix":
			passph = d + passph
		case "between":
			passph = insertBetween(passph, d)
		default:
			passph = passph + d
		}
	}

	if opts.AddSymbol && len(opts.SymbolSet) > 0 {
		idx := rand.GetRand(0, int64(len(opts.SymbolSet))-1)
		sym := string(opts.SymbolSet[idx])
		switch opts.SymbolPosition {
		case "prefix":
			passph = sym + passph
		case "between":
			passph = insertBetween(passph, sym)
		default:
			passph = passph + sym
		}
	}

	return passph, nil
}

// PasswordOptions controls advanced password generation.
type PasswordOptions struct {
	Length        int    // total length
	MinDigits     int    // at least this many digits
	MinSymbols    int    // at least this many symbols
	AllowUpper    bool   // include uppercase letters
	AllowLower    bool   // include lowercase letters
	AllowRepeat   bool   // allow character repetition
	CustomSymbols string // optional symbol set
}

// GeneratePasswordAdvanced creates a policy-friendly password.
func GeneratePasswordAdvanced(opts PasswordOptions) (string, error) {
	if opts.Length == 0 {
		opts.Length = int(minPasswordLen)
	}
	if opts.Length < int(minPasswordLen) {
		opts.Length = int(minPasswordLen)
	}
	if opts.Length > int(maxPasswordLen) {
		opts.Length = int(maxPasswordLen)
	}
	if opts.AllowLower == false && opts.AllowUpper == false {
		opts.AllowLower = true
	}

	genInput := &password.GeneratorInput{}
	if opts.CustomSymbols != "" {
		genInput.Symbols = opts.CustomSymbols
	}
	gen, err := password.NewGenerator(genInput)
	if err != nil {
		return "", err
	}

	noUpper := !opts.AllowUpper

	res := gen.MustGenerate(
		opts.Length,
		opts.MinDigits,
		opts.MinSymbols,
		noUpper,
		opts.AllowRepeat,
	)

	return res, nil
}
