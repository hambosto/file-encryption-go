package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// Constants for AES-GCM encryption
const (
	saltSize          = 16      // Size of the salt in bytes
	nonceSize         = 12      // Size of the nonce in bytes
	keyDerivationN    = 1 << 18 // CPU/memory cost parameter for scrypt
	keyDerivationR    = 8       // Block size parameter for scrypt
	keyDerivationP    = 1       // Parallelization parameter for scrypt
	keyDerivationLen  = 32      // Length of the derived key in bytes
	minCiphertextSize = 28      // Minimum size of the ciphertext (salt + nonce + tag)
)

// Encryptor handles both encryption and decryption using AES-GCM
type Encryptor struct {
	password []byte // User-provided password for key derivation
}

// NewEncryptor creates a new Encryptor instance with the provided password
func NewEncryptor(password string) *Encryptor {
	return &Encryptor{password: []byte(password)}
}

// addPadding adds PKCS#7 padding to the plaintext to make its length a multiple of the block size
func addPadding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padText...)
}

// removePadding removes PKCS#7 padding from the padded plaintext
func removePadding(paddedText []byte) ([]byte, error) {
	if len(paddedText) == 0 {
		return nil, errors.New("padded text is empty")
	}
	padding := int(paddedText[len(paddedText)-1])
	if padding > len(paddedText) {
		return nil, errors.New("invalid padding")
	}
	return paddedText[:len(paddedText)-padding], nil
}

// deriveKey derives a cryptographic key from the password and salt using the scrypt key derivation function
func deriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, keyDerivationN, keyDerivationR, keyDerivationP, keyDerivationLen)
}

// encrypt encrypts plaintext using AES-GCM
func (e *Encryptor) encrypt(plaintext []byte) ([]byte, error) {
	// Generate a random salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Derive a key using scrypt
	key, err := deriveKey(e.password, salt)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new AES-GCM instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the plaintext and append the nonce and ciphertext
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return append(salt, append(nonce, ciphertext...)...), nil
}

// decrypt decrypts ciphertext using AES-GCM
func (e *Encryptor) decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < minCiphertextSize {
		return nil, errors.New("invalid ciphertext length")
	}

	// Extract salt, nonce, and the actual ciphertext from the combined ciphertext
	salt := ciphertext[:saltSize]
	nonce := ciphertext[saltSize : saltSize+nonceSize]
	ciphertextBytes := ciphertext[saltSize+nonceSize:]

	// Derive the key using scrypt
	key, err := deriveKey(e.password, salt)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new AES-GCM instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, err
	}

	return removePadding(plaintext)
}

// Encrypt encrypts a plaintext string using AES-GCM and returns a base64-encoded ciphertext string
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	// Convert plaintext string to byte slice and add padding
	plaintextBytes := addPadding([]byte(plaintext), aes.BlockSize)

	// Encrypt the plaintext
	ciphertext, err := e.encrypt(plaintextBytes)
	if err != nil {
		return "", err
	}

	// Encode ciphertext to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext string using AES-GCM and returns the plaintext string
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	// Decode base64-encoded ciphertext
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Decrypt ciphertext
	plaintext, err := e.decrypt(decoded)
	if err != nil {
		return "", err
	}

	// Convert plaintext byte slice to string
	return string(plaintext), nil
}
