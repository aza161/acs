package server

import (
	acsDB "acs/internal/db"
	"acs/internal/jsonutils"
	jwtutils "acs/pkg/auth/jwt"
	"acs/pkg/passutils"
	"bytes"
	"errors"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	jwtPrivateKey = ".keys/jwt/privateKey.pem" // used for JWT
	jwtPublicKey  = ".keys/jwt/publicKey.pem"
	privteKey     = ".keys/privateKey.pem" // used for TLS
	publicKey     = ".keys/publicKey.pem"
)

var (
	fileNotFound = errors.New("file not found")
)

type Server struct {
	db            *gorm.DB
	JwtPrivateKey string
	JwtPublicKey  string
	PrivateKey    string
	PublicKey     string
}

func (s *Server) registerAccount(c *gin.Context) {
	var json jsonutils.RegisterRequest
	if err := c.BindJSON(&json); err != nil {
		c.IndentedJSON(400, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	err := acsDB.CreateUser(s.db, json.UserName, json.Password, json.UniqueDeviceID)

	if err != nil {
		c.IndentedJSON(409, gin.H{"error": "user name is already taken please pick another one"})
		return
	}

	c.IndentedJSON(201, gin.H{"info": "user created successfully"})
}

func (s *Server) userLogin(c *gin.Context) {
	var json jsonutils.LoginRequest
	if err := c.BindJSON(&json); err != nil {
		c.IndentedJSON(400, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	user, err := acsDB.GetUser(s.db, json.UserName)
	if err != nil {
		c.IndentedJSON(401, gin.H{"error": "invalid user name or password"})
		return
	}

	passwordHash, err := passutils.Argon2ID(json.Password, user.Salt, user.Threads)
	if err != nil {
		log.Printf("Internal server error: %v", err)
		c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
		return
	}

	if !bytes.Equal(passwordHash, user.PasswordHash) {
		c.IndentedJSON(401, gin.H{"error": "either user name is already taken or password is wrong"})
		return
	}

	token, err := jwtutils.GenerateJWTEd25519(json.UserName, s.JwtPrivateKey)
	if err != nil {
		log.Printf("Internal server error: %v", err)
		c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
		return
	}

	c.IndentedJSON(200, gin.H{"token": token})
}

func (s *Server) syncData(c *gin.Context) {
	var json jsonutils.SyncRequest
	if err := c.BindJSON(&json); err != nil {
		c.IndentedJSON(400, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	tokePtr, err := jwtutils.ParseJWTEd25519(json.JWT, s.JwtPublicKey)
	if err != nil {
		c.IndentedJSON(401, gin.H{"error": "invalid or expired token"})
		return
	}

	userName, err := tokePtr.Claims.GetSubject()
	if err != nil {
		c.IndentedJSON(401, gin.H{"error": "token is not valid"})
		return
	}

	user, err := acsDB.GetUser(s.db, userName)
	if err != nil {
		log.Printf("Internal server error: %v", err)
		c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
		return
	}

	if user.UpdatedAt.UTC().Compare(json.UpdateDate.UTC()) == -1 && !json.IsMerged && user.EditedBy == json.UniqueDeviceID {
		err := overWriteFile(user, json.EncryptedData)
		if err != nil {
			log.Printf("Internal server error: %v", err)
			c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
			return
		}
		c.JSON(201, gin.H{"status": "created"})
		return
	}

	if !user.UpdatedAt.UTC().Equal(json.UpdateDate.UTC()) && !json.IsMerged {
		c.IndentedJSON(409, user)
		return
	}

	if user.UpdatedAt.UTC().Equal(json.UpdateDate.UTC()) && !json.IsMerged {
		c.JSON(200, gin.H{"status": "ok"})
		return
	}

	if json.IsMerged {
		err := overWriteFile(user, json.EncryptedData)
		if err != nil {
			log.Printf("Internal server error: %v", err)
			c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
			return
		}
		c.JSON(201, gin.H{"status": "created"})
		return
	}

	log.Printf("Internal server error: %v", err)
	c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
}

func overWriteFile(user acsDB.User, json string) error {
	file, err := os.Create(".users/" + user.URI)
	if err != nil {
		return err
	}
	defer file.Close()

	n, err := file.Write([]byte(json))
	if err != nil {
		return err
	}
	if n != len(json) {
		return errors.New("something went wrong")
	}

	return nil
}

func getEncryptedData(user acsDB.User) (string, error) {
	file, err := os.ReadFile(".users/" + user.URI)
	if err != nil {
		return "", fileNotFound
	}
	return string(file), nil
}
