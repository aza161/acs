package jsonutils

import (
	encrypt "acs/pkg/crypt"
	"acs/pkg/passutils"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"time"

	"github.com/google/uuid"
)

type EncryptedPasswords struct {
	Salt          string    `json:"salt"`
	Time          uint32    `json:"time"`
	Memory        uint32    `json:"memory"`
	Threads       uint8     `json:"threads"`
	Nonce         string    `json:"gcm_nonce"`
	UpdateDate    time.Time `json:"update_date"`
	EncryptedData string    `json:"blob"`
}

// A passowrd entry model, exclusively used on client side
type Entry struct {
	URL        string    `json:"url"`
	UserName   string    `json:"username"`
	Password   string    `json:"password"`
	CreateDate time.Time `json:"create_date"`
	UpdateDate time.Time `json:"update_date"`
	AccessDate time.Time `json:"access_date"`
	Info       string    `json:"notes,omitempty"`
	IsDeleted  bool      `json:"is_deleted"`
}

type RegisterRequest struct {
	UserName       string    `json:"user_name" binding:"required"`
	Password       string    `json:"password" binding:"required"`
	UniqueDeviceID uuid.UUID `json:"uuid" binding:"required"`
}

type LoginRequest struct {
	UserName string `json:"user_name" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type SyncRequest struct {
	JWT            string             `json:"token" binding:"required"`
	UniqueDeviceID uuid.UUID          `json:"uuid" binding:"required"`
	UpdateDate     time.Time          `json:"update_date" binding:"required"`
	IsMerged       bool               `json:"is_merged" binding:"required"`
	EncryptedData  EncryptedPasswords `json:"vault" binding:"required"`
}

// A function that generates indented JSON stings
func GenerateJson(object any) ([]byte, error) {
	return json.MarshalIndent(object, "", "  ")
}

// Helper function to create a unique key for an entry
func (e Entry) Key() string {
	// Assuming URL + UserName uniquely identifies an entry
	return e.URL + ":" + e.UserName
}

// A function that takes a password, generates an encryption key using Argon2ID,
// converts the entries list to a JSON and then encrypts it using AES-GCM.
// Returns EncryptPasswords type which contains the encrypted entries in Base64
// and the other necessary parameters used for AES-GCM and Argon2ID.
func EncryptPasswords(password string, entries []Entry) (EncryptedPasswords, error) {
	// Gneerate random salt
	salt := make([]byte, passutils.SaltLen)
	rand.Read(salt)

	// Generate encryption key using Argon2ID
	threads := runtime.NumCPU()
	key, err := passutils.Argon2ID(password, salt, uint8(threads))
	if err != nil {
		return EncryptedPasswords{}, err
	}

	// Serialized password entries
	byteObj, err := GenerateJson(entries)

	nonce, _ := encrypt.GenerateNonce(12)

	// Encrypted password list
	encryptedData, err := encrypt.EncryptAESGCM(key, nonce, byteObj, []byte("Encrypted_Passwords"))
	if err != nil {
		return EncryptedPasswords{}, err
	}

	// Converetd to Base64 because JSON supports stings only
	jsonData := EncryptedPasswords{
		EncryptedData: base64.StdEncoding.EncodeToString(encryptedData),
		Salt:          base64.StdEncoding.EncodeToString(salt),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Memory:        passutils.Memory,
		Time:          passutils.Time,
		Threads:       uint8(threads),
	}
	return jsonData, nil
}

func DecryptPasswords(password string, passowrds EncryptedPasswords) ([]Entry, error) {
	// Derrive Encryption key from the passowrd
	salt, _ := base64.StdEncoding.DecodeString(passowrds.Salt)
	key, err := passutils.Argon2ID(password, salt, passowrds.Threads)
	if err != nil {
		return nil, err
	}

	// Decode the nonce
	nonce, err := base64.StdEncoding.DecodeString(passowrds.Nonce)
	if err != nil {
		return nil, err
	}

	// Decode the passwords
	encryptedPasswords, err := base64.StdEncoding.DecodeString(passowrds.EncryptedData)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	decryptedData, err := encrypt.DecryptAESGCM(key, nonce, encryptedPasswords, []byte("Encrypted_Passwords"))
	if err != nil {
		return nil, err
	}

	// De-Serialzie the data
	var entries []Entry
	err = json.Unmarshal(decryptedData, &entries)
	return entries, err
}
