package main

import (
	"acs/pkg/passutils"
	"fmt"

	"github.com/sethvargo/go-password/password"
)

// Just used to check if everything is functioning as it was intended to be.
func main() {
	pass := passutils.GeneratePassword(password.Symbols, false)
	symbols := password.Symbols
	//fmt.Println(pass)
	fmt.Println(passutils.CheckPasswordStrength(pass, nil, &symbols, 1))
	passph, _ := passutils.GeneratePassphrase(7)
	fmt.Println(passph)
}
