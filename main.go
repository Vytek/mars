package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	// Sostituisci con il percorso reale del tuo pacchetto.
	// Se hai tutto nello stesso file main.go, non serve importarlo.
	"gomars/mars" 
)

func main() {
	// 1. Definiamo una chiave (128 bit = 16 byte). 
	// MARS supporta chiavi da 128 a 448 bit (multipli di 32).
	key := []byte("ChiaveSegreta123") // Esattamente 16 caratteri/byte

	// Inizializziamo il nostro cifrario MARS
	block, err := mars.NewCipherFromBytes(key)
	if err != nil {
		log.Fatalf("Errore nella creazione del cifrario: %v", err)
	}

	fmt.Println("==================================================")
	fmt.Println("1. TEST DI BASE (Singolo Blocco da 16 Byte)")
	fmt.Println("==================================================")

	// Il testo in chiaro deve essere esattamente di 16 byte per il test base
	plaintextBlock := []byte("Test di 16 bytes")
	ciphertextBlock := make([]byte, mars.BlockSize)
	decryptedBlock := make([]byte, mars.BlockSize)

	// Cifratura del singolo blocco
	block.Encrypt(ciphertextBlock, plaintextBlock)
	fmt.Printf("Testo originale : %s\n", string(plaintextBlock))
	fmt.Printf("Cifrato (Hex)   : %x\n", ciphertextBlock)

	// Decifratura del singolo blocco
	block.Decrypt(decryptedBlock, ciphertextBlock)
	fmt.Printf("Testo decifrato : %s\n\n", string(decryptedBlock))


	fmt.Println("==================================================")
	fmt.Println("2. TEST REALE (Testo lungo + Modalità CBC)")
	fmt.Println("==================================================")

	// Dati di lunghezza arbitraria
	messaggioSegreto := "Questo è un messaggio super segreto molto più lungo di 16 byte!"
	plaintext := []byte(messaggioSegreto)

	// Applichiamo il padding PKCS#7 poiché CBC richiede che i dati
	// siano un multiplo esatto della dimensione del blocco (16 byte).
	paddingLen := block.BlockSize() - len(plaintext)%block.BlockSize()
	padtext := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	plaintextPadded := append(plaintext, padtext...)

	// Creiamo un buffer per contenere sia l'IV (Vettore di Inizializzazione) che i dati cifrati
	ciphertext := make([]byte, block.BlockSize()+len(plaintextPadded))
	iv := ciphertext[:block.BlockSize()]

	// Riempiamo l'IV con dati casuali crittograficamente sicuri
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("Errore nella generazione dell'IV: %v", err)
	}

	// Cifriamo utilizzando la modalità CBC standard di Go, passando il nostro blocco MARS
	modeEnc := cipher.NewCBCEncrypter(block, iv)
	modeEnc.CryptBlocks(ciphertext[block.BlockSize():], plaintextPadded)

	fmt.Printf("Testo originale   : %s\n", messaggioSegreto)
	fmt.Printf("Cifrato CBC (Hex) : %x\n", ciphertext)

	// ---- FASE DI DECIFRATURA CBC ---- //

	// Estraiamo l'IV e il messaggio cifrato dal buffer completo
	ivDec := ciphertext[:block.BlockSize()]
	ciphertextActual := ciphertext[block.BlockSize():]

	// Decifriamo
	modeDec := cipher.NewCBCDecrypter(block, ivDec)
	decryptedCBC := make([]byte, len(ciphertextActual))
	modeDec.CryptBlocks(decryptedCBC, ciphertextActual)

	// Rimuoviamo il padding PKCS#7
	unpaddingLen := int(decryptedCBC[len(decryptedCBC)-1])
	decryptedPaddedLess := decryptedCBC[:len(decryptedCBC)-unpaddingLen]

	fmt.Printf("Testo decifrato   : %s\n", string(decryptedPaddedLess))
}