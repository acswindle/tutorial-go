package internal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/acswindle/tutorial-go/database"
	"github.com/acswindle/tutorial-go/templates"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

type ResponseToken struct {
	Token   string `json:"access_token"`
	Type    string `json:"token_type"`
	Expires int    `json:"expires_in"`
}

type JWTClaims struct {
	UserId    int32  `json:"user_id"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	Auth      bool   `json:"authorized"`
	DeriveKey []byte `json:"deriveKey"`
	jwt.RegisteredClaims
}

// deriveKey generates an encryption key from a password and salt
func deriveKey(password []byte, salt []byte) []byte {
	// PBKDF2 with SHA256, 100,000 iterations, 32-byte key (AES-256)
	return pbkdf2.Key(password, salt, 100000, 32, sha256.New)
}

// EncryptedData represents data stored in the database
type EncryptedData struct {
	Nonce      []byte
	Ciphertext []byte
}

// encrypt encrypts plaintext using AES-GCM
func encrypt(key, plaintext []byte) (EncryptedData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedData{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedData{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedData{}, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return EncryptedData{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// decrypt decrypts ciphertext using AES-GCM
func decrypt(key []byte, data EncryptedData) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, data.Nonce, data.Ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func generateJWT(user database.GetCredentialsRow) (ResponseToken, error) {
	jwtSecret, secretSet := os.LookupEnv("JWT_SECRET")
	if !secretSet {
		return ResponseToken{}, fmt.Errorf("JWT_SECRET not set")
	}
	jwtExpireTime, setExp := os.LookupEnv("JWT_EXPIRE_TIME")
	if !setExp {
		return ResponseToken{}, fmt.Errorf("JWT_EXPIRE_TIME not set")
	}
	if !setExp {
		return ResponseToken{}, fmt.Errorf("JWT_EXPIRE_TIME not set")
	}
	expireTime, err := strconv.Atoi(jwtExpireTime)
	if err != nil {
		return ResponseToken{}, fmt.Errorf("JWT_EXPIRE_TIME must be an integer")
	}
	claims := jwt.MapClaims{
		"user_id":    user.ID,
		"exp":        time.Now().Add(time.Second * time.Duration(expireTime)).Unix(),
		"iat":        time.Now().Unix(),
		"authorized": true,
		"deriveKey":  deriveKey(user.Password, user.Salt),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return ResponseToken{}, fmt.Errorf("failed to generate JWT token: %v", err)
	}
	return ResponseToken{
		Token:   tokenString,
		Type:    "Bearer",
		Expires: expireTime,
	}, nil
}

func ValidateToken(w http.ResponseWriter, r *http.Request) (JWTClaims, error) {
	jwtSecret, secretSet := os.LookupEnv("JWT_SECRET")
	if !secretSet {
		http.Error(w, "JWT_SECRET not set", http.StatusInternalServerError)
		return JWTClaims{}, fmt.Errorf("JWT_SECRET not set")
	}
	auth, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "token not set", http.StatusUnauthorized)
		return JWTClaims{}, fmt.Errorf("token not set")
	}
	var tokenClaims JWTClaims
	token, err := jwt.ParseWithClaims(auth.Value, &tokenClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return JWTClaims{}, err
	}
	if !token.Valid {
		http.Error(w, "token not valid", http.StatusUnauthorized)
		return JWTClaims{}, fmt.Errorf("token not valid")
	}
	http.Error(w, "token not valid", http.StatusUnauthorized)
	return tokenClaims, nil
}

func SecurityRoutes(ctx context.Context, queries *database.Queries) {
	// Render the sign up page
	http.HandleFunc("/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		templates.SignUp().Render(r.Context(), w)
	})

	// Register a new user
	http.HandleFunc("POST /auth/register", func(w http.ResponseWriter, r *http.Request) {
		// Parse the form
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		username := r.Form.Get("username")
		if username == "" {
			http.Error(w, "username not set", http.StatusBadRequest)
			return
		}
		rawPassword := r.Form.Get("password")
		if rawPassword == "" {
			http.Error(w, "password not set", http.StatusBadRequest)
			return
		}
		email := r.Form.Get("email")
		if email == "" {
			http.Error(w, "email not set", http.StatusBadRequest)
			return
		}

		// Hash the password
		password := []byte(rawPassword)
		salt, err := generateSalt()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		password, err = bcrypt.GenerateFromPassword(append(password, salt...), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Insert the user
		_, err = queries.InsertUsers(ctx, database.InsertUsersParams{
			Username: username,
			Email:    email,
			Password: password,
			Salt:     salt,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to the login page
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
	})

	// Obtain login token
	http.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		// Parse the form
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "password" {
			http.Error(w, "grant_type must be password", http.StatusBadRequest)
			return
		}
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if username == "" || password == "" {
			http.Error(w, "username or password not set", http.StatusBadRequest)
			return
		}

		// Get the user
		user, err := queries.GetCredentials(ctx, username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Compare the password
		if err := bcrypt.CompareHashAndPassword(user.Password, append([]byte(password), user.Salt...)); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		token, err := generateJWT(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set the response
		cookie := http.Cookie{
			Name:     "token",
			Value:    token.Token,
			SameSite: http.SameSiteLaxMode,
			HttpOnly: true,
			Path:     "/",
		}
		http.SetCookie(w, &cookie)

		// Redirect to the home page
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Render the login page
	http.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		templates.LogIn().Render(r.Context(), w)
	})

	// Render handle logout
	http.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		deleteCookie(w, "token")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}
