package encryption

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/encryption-go/aes"
)

// EncryptionService handles file encryption and decryption
type EncryptionService struct {
	reader *bufio.Reader
}

// NewEncryptionService creates a new instance of EncryptionService
func NewEncryptionService(reader *bufio.Reader) *EncryptionService {
	return &EncryptionService{reader: bufio.NewReader(reader)}
}

// promptInput prompts the user for input with the given message
func (es *EncryptionService) promptInput(message string) (string, error) {
	fmt.Print(message)
	var input string
	_, err := fmt.Fscanln(es.reader, &input)
	return input, err
}

// EncryptFile handles the encryption process
func (es *EncryptionService) EncryptFile() {
	inputFilePath, err := es.promptInput("Enter the path to the file to encrypt: ")
	if err != nil {
		fmt.Printf("Failed to read the input file path: %v\n", err)
		return
	}

	password, err := es.promptInput("Enter the password: ")
	if err != nil {
		fmt.Printf("Failed to read the password: %v\n", err)
		return
	}

	// Generate the output file path
	outputFilePath := strings.TrimSuffix(inputFilePath, filepath.Ext(inputFilePath)) + "_encrypted" + filepath.Ext(inputFilePath)

	data, err := os.ReadFile(inputFilePath)
	if err != nil {
		fmt.Printf("Failed to read the file: %v\n", err)
		return
	}

	encryptor := aes.NewEncryptor(password)
	encryptedData, err := encryptor.Encrypt(string(data))
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		return
	}

	err = os.WriteFile(outputFilePath, []byte(encryptedData), 0644)
	if err != nil {
		fmt.Printf("Failed to write the encrypted file: %v\n", err)
		return
	}

	fmt.Println("File encrypted successfully!")
}

// DecryptFile handles the decryption process
func (es *EncryptionService) DecryptFile() {
	inputFilePath, err := es.promptInput("Enter the path to the encrypted file: ")
	if err != nil {
		fmt.Printf("Failed to read the input file path: %v\n", err)
		return
	}

	password, err := es.promptInput("Enter the password: ")
	if err != nil {
		fmt.Printf("Failed to read the password: %v\n", err)
		return
	}

	// Generate the output file path
	outputFilePath := strings.TrimSuffix(inputFilePath, filepath.Ext(inputFilePath)) + "_decrypted" + filepath.Ext(inputFilePath)

	encryptedData, err := os.ReadFile(inputFilePath)
	if err != nil {
		fmt.Printf("Failed to read the file: %v\n", err)
		return
	}

	encryptor := aes.NewEncryptor(password)
	decryptedData, err := encryptor.Decrypt(string(encryptedData))
	if err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		return
	}

	err = os.WriteFile(outputFilePath, []byte(decryptedData), 0644)
	if err != nil {
		fmt.Printf("Failed to write the decrypted file: %v\n", err)
		return
	}

	fmt.Println("File decrypted successfully!")
}
