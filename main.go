package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hambosto/encryption-go/encryption"
)

const asciiArt = `
                                    __  _                             
  ___  ____  ____________  ______  / /_(_)___  ____        ____ _____ 
 / _ \/ __ \/ ___/ ___/ / / / __ \/ __/ / __ \/ __ \______/ __ '/ __ \
/  __/ / / / /__/ /  / /_/ / /_/ / /_/ / /_/ / / / /_____/ /_/ / /_/ /
\___/_/ /_/\___/_/   \__, / .___/\__/_/\____/_/ /_/      \__, /\____/ 
                    /____/_/                            /____/         
	
					
`

func main() {
	reader := bufio.NewReader(os.Stdin)
	service := encryption.NewEncryptionService(reader)

	fmt.Print(asciiArt)
	fmt.Println("File Encryption/Decryption CLI")
	fmt.Println("------------------------------")

	for {
		fmt.Println("\nChoose an option:")
		fmt.Println("1. Encrypt a file")
		fmt.Println("2. Decrypt a file")
		fmt.Println("3. Exit")
		fmt.Print("Enter option (1, 2, or 3): ")

		option, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Failed to read the option: %v\n", err)
			continue
		}
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			service.EncryptFile()
		case "2":
			service.DecryptFile()
		case "3":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid option. Please enter 1, 2, or 3.")
		}
	}
}
