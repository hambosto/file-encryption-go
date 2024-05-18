package aes

import (
	"testing"
)

// TestEncryptDecrypt tests the encryption and decryption process
func TestEncryptDecrypt(t *testing.T) {
	password := "strongpassword"
	plaintext := "This is a secret message."

	encryptor := NewEncryptor(password)

	// Encrypt the plaintext
	encryptedText, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt the ciphertext
	decryptedText, err := encryptor.Decrypt(encryptedText)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Check if the decrypted text matches the original plaintext
	if decryptedText != plaintext {
		t.Errorf("Decrypted text does not match the original plaintext.\nExpected: %s\nGot: %s", plaintext, decryptedText)
	}
}

// TestDecryptWithWrongPassword tests the decryption process with a wrong password
func TestDecryptWithWrongPassword(t *testing.T) {
	password := "strongpassword"
	wrongPassword := "wrongpassword"
	plaintext := "This is a secret message."

	encryptor := NewEncryptor(password)

	// Encrypt the plaintext
	encryptedText, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt the ciphertext with the wrong password
	wrongEncryptor := NewEncryptor(wrongPassword)
	_, err = wrongEncryptor.Decrypt(encryptedText)
	if err == nil {
		t.Error("Expected decryption to fail with the wrong password, but it succeeded")
	}
}

// TestEncryptDecryptEmptyString tests encryption and decryption of an empty string
func TestEncryptDecryptEmptyString(t *testing.T) {
	password := "strongpassword"
	plaintext := ""

	encryptor := NewEncryptor(password)

	// Encrypt the plaintext
	encryptedText, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt the ciphertext
	decryptedText, err := encryptor.Decrypt(encryptedText)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Check if the decrypted text matches the original plaintext
	if decryptedText != plaintext {
		t.Errorf("Decrypted text does not match the original plaintext.\nExpected: %s\nGot: %s", plaintext, decryptedText)
	}
}

// TestEncryptDecryptDifferentMessages tests encryption and decryption of different messages
func TestEncryptDecryptDifferentMessages(t *testing.T) {
	password := "strongpassword"
	messages := []string{
		"Short",
		"Another secret message.",
		"Yet another different message, slightly longer.",
		"1234567890",
		"!@#$%^&*()_+",
		"",
	}

	encryptor := NewEncryptor(password)

	for _, plaintext := range messages {
		// Encrypt the plaintext
		encryptedText, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed for message '%s': %v", plaintext, err)
		}

		// Decrypt the ciphertext
		decryptedText, err := encryptor.Decrypt(encryptedText)
		if err != nil {
			t.Fatalf("Decryption failed for message '%s': %v", plaintext, err)
		}

		// Check if the decrypted text matches the original plaintext
		if decryptedText != plaintext {
			t.Errorf("Decrypted text does not match the original plaintext for message '%s'.\nExpected: %s\nGot: %s", plaintext, plaintext, decryptedText)
		}
	}
}
