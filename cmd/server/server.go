package main

import (
	"acs/internal/db"
	acsDB "acs/internal/db"
	"acs/internal/jsonutils"
	jwtutils "acs/pkg/auth/jwt"
	"acs/pkg/passutils"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	jwtPrivateKey = ".keys/jwt/privateKey.pem" // used for JWT
	jwtPublicKey  = ".keys/jwt/publicKey.pem"
	privteKey     = ".keys/privateKey.pem" // used for TLS
	publicKey     = ".keys/certificate.crt"
	dbPath        = ".db/db.sqlite"
	port          = 443 // you can change this for testing purposes.
)

var (
	fileNotFound = errors.New("file not found")
)

type Server struct {
	db                *gorm.DB
	JwtPrivateKey     string
	JwtPublicKey      string
	PublicCertificate string
	PublicKey         string
}

func (s *Server) setUpServerAndRouter(dbPath string, jwtPrivateKey, jwtPublicKey, privateKey, publicKey string) *gin.Engine {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil
	}
	s.db = db
	s.JwtPrivateKey = jwtPrivateKey
	s.JwtPublicKey = jwtPublicKey
	s.PublicCertificate = privateKey
	s.PublicKey = publicKey
	router := gin.Default()
	router.POST("/register", s.registerAccount)
	router.POST("/login", s.userLogin)
	router.POST("/sync", s.syncData)
	return router
}

func main() {
	fmt.Println("Welcome to acs server...")
	fmt.Println("Make sure to install SQLite3 on your system")
	fmt.Println("Make sure to run serversetup.sh script in the same directory of the server binary before continuing")
	var ans string
	for {
		fmt.Println("Continue? [y]es [n]o")
		fmt.Scanf("%s", &ans)
		if ans == "y" || ans == "Y" {
			break
		} else if ans == "n" || ans == "N" {
			os.Exit(1)
		} else {
			fmt.Println("Invalid input. Please enter 'y' or 'n'.")
		}
	}

	var s Server
	router := s.setUpServerAndRouter(dbPath, jwtPrivateKey, jwtPublicKey, privteKey, publicKey)
	s.db.AutoMigrate(&db.User{})
	fmt.Printf("Server started listening on port %d\n", port)
	strPort := fmt.Sprintf(":%d", port)
	err := router.RunTLS(strPort, s.PublicKey, s.PublicCertificate)
	if err != nil {
		log.Fatal(err)
	}
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

	user, err := acsDB.GetUser(s.db, json.UserName)
	if err != nil {
		c.IndentedJSON(500, gin.H{"error": "internal error creating user file"})
		return
	}

	if err := makeDataFile(user); err != nil {
		log.Printf("Failed to create data file: %v", err)
		c.IndentedJSON(500, gin.H{"error": "failed to initialize user data"})
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
		log.Printf("Client side error: %v", err)
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
		str, _ := jsonutils.GenerateJson(json.EncryptedData)
		err := overWriteFile(user, string(str))
		if err != nil {
			log.Printf("Internal server error: %v", err)
			c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
			return
		}
		c.JSON(201, gin.H{"status": "created"})
		return
	}

	if !user.UpdatedAt.UTC().Equal(json.UpdateDate.UTC()) && !json.IsMerged {
		str, err := getEncryptedData(user)
		if err != nil {
			log.Printf("Internal server error: %v", err)
			c.IndentedJSON(500, gin.H{"error": "something went wrong please try again"})
			return
		}
		c.Data(409, "application/json", []byte(str))
		return
	}

	if user.UpdatedAt.UTC().Equal(json.UpdateDate.UTC()) && !json.IsMerged {
		c.JSON(200, gin.H{"status": "ok"})
		return
	}

	if json.IsMerged {
		str, _ := jsonutils.GenerateJson(json.EncryptedData)
		err := overWriteFile(user, string(str))
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

func makeDataFile(user acsDB.User) error {
	// Ensure directory exists
	if err := os.MkdirAll(".users", 0700); err != nil {
		return fmt.Errorf("failed to create users directory: %w", err)
	}

	// Create the file (truncate if it exists)
	file, err := os.Create(".users/" + user.URI)
	if err != nil {
		return fmt.Errorf("failed to create user data file: %w", err)
	}
	defer file.Close()

	// Initialize with an empty encrypted vault placeholder
	emptyVault := jsonutils.EncryptedPasswords{}
	data, err := jsonutils.GenerateJson(emptyVault)
	if err != nil {
		return fmt.Errorf("failed to marshal empty vault: %w", err)
	}

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write user data file: %w", err)
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
