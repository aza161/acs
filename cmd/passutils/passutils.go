package main

import (
	"acs/internal/jsonutils"
	"acs/pkg/passutils"
	"fmt"
	"time"
)

// Just used to check if everything is functioning as it was intended to be.
func main() {
	passph, _ := passutils.GeneratePassphrase(7)
	fmt.Println(passph)

	List := []jsonutils.Entry{
		{URL: "google.com", UserName: "ahmad", Password: "test123", CreateDate: time.Now().UTC(), AccessDate: time.Now().UTC(), Info: ""},
		{URL: "github.com", UserName: "aza161", Password: "realestOne23", CreateDate: time.Now().UTC(), AccessDate: time.Now().UTC(), Info: ""},
		{URL: "linkedin.com", UserName: "him", Password: "idknidcnidts", CreateDate: time.Now().UTC(), AccessDate: time.Now().UTC(), Info: ""},
	}

	List = append(List, jsonutils.Entry{URL: "example.com", UserName: "evil", Password: "evesdropperwillhear", CreateDate: time.Now().UTC(), AccessDate: time.Now().UTC(), Info: ""})
	passwords, err := jsonutils.EncryptPasswords(passph, List)
	str, _ := jsonutils.GenerateJson(passwords)
	fmt.Println(string(str), err)
	password, err := jsonutils.DecryptPasswords(passph, passwords)
	str, _ = jsonutils.GenerateJson(password)
	fmt.Println(string(str))
}
