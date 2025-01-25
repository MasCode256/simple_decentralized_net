package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type EncryptedMessage struct {
	IV      string `json:"iv"`
	Key     string `json:"key"`
	Message string `json:"message"`
}

func NewEncryptedMessage(jsonStr string) (EncryptedMessage, error) {
	var this EncryptedMessage

	err := json.Unmarshal([]byte(jsonStr), &this)
	if err != nil {
		log.Fatal(err)
		return this, err
	}

	return this, nil
}

func generateRandomString(length int) (string, error) {
	// Генерируем случайные байты
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Кодируем байты в строку Base64
	return base64.RawStdEncoding.EncodeToString(bytes)[:length], nil
}

// Генерация пары ключей RSA
func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// Кодирование приватного ключа в Base64
func encodePrivateKey(priv *rsa.PrivateKey) string {
	privASN1 := x509.MarshalPKCS1PrivateKey(priv)
	return base64.StdEncoding.EncodeToString(privASN1)
}

// Кодирование публичного ключа в Base64
func encodePublicKey(pub *rsa.PublicKey) string {
	pubASN1 := x509.MarshalPKCS1PublicKey(pub)
	return base64.StdEncoding.EncodeToString(pubASN1)
}

// Декодирование приватного ключа из Base64
func decodePrivateKey(encoded string) (*rsa.PrivateKey, error) {
	privASN1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(privASN1)
}

// Декодирование публичного ключа из Base64
func decodePublicKey(encoded string) (*rsa.PublicKey, error) {
	pubASN1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PublicKey(pubASN1)
}

// Функция для дополнения данных до размера блока
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Функция для удаления дополнения
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding")
	}
	return data[:(length - unpadding)], nil
}

// Шифрование сообщения с использованием AES
func encryptAES(key []byte, plaintext []byte) (string, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", nil, err
	}

	// Дополнение текста перед шифрованием
	paddedText := pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	return base64.StdEncoding.EncodeToString(ciphertext), iv, nil
}

// Расшифрование сообщения с использованием AES
func decryptAES(key []byte, ciphertext string, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertextBytes, _ := base64.StdEncoding.DecodeString(ciphertext)
	if len(ciphertextBytes)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertextBytes))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertextBytes)

	// Удаление дополнения после расшифрования
	return unpad(plaintext)
}

// Шифрование AES ключа с использованием RSA
func encryptRSA(pub *rsa.PublicKey, aesKey []byte) (string, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// Расшифрование AES ключа с использованием RSA
func decryptRSA(priv *rsa.PrivateKey, encryptedKey string) ([]byte, error) {
	encryptedKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedKey)
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKeyBytes, nil)
}

func encrypt(pk *rsa.PublicKey, str []byte) (string, error) {
	aesKey, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	encryptedKey, err := encryptRSA(pk, []byte(aesKey))
	if err != nil {
		return "", err
	}

	encryptedStr, iv, err := encryptAES([]byte(aesKey), str)
	if err != nil {
		return "", err
	}

	// Кодируем IV в Base64 и формируем JSON
	encryptedMessage := EncryptedMessage{
		Key:     encryptedKey,
		IV:      base64.StdEncoding.EncodeToString(iv), // Кодируем IV
		Message: encryptedStr,
	}

	jsonResult, err := json.Marshal(encryptedMessage)
	if err != nil {
		return "", err
	}

	return string(jsonResult), nil
}

func decrypt(sk *rsa.PrivateKey, str string) (string, error) {
	encryptedMessage, err := NewEncryptedMessage(str)
	if err != nil {
		return "", err
	}

	aesKey, err := decryptRSA(sk, encryptedMessage.Key)
	if err != nil {
		return "", err
	}

	// Декодируем IV из Base64
	ivBytes, err := base64.StdEncoding.DecodeString(encryptedMessage.IV)
	if err != nil {
		return "", err
	}

	decryptedMessage, err := decryptAES(aesKey, encryptedMessage.Message, ivBytes)
	if err != nil {
		return "", err
	}

	return string(decryptedMessage), nil
}

// Создание цифровой подписи
func createSignature(priv *rsa.PrivateKey, message []byte) (string, error) {
	hash := sha256.New()
	hash.Write(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Проверка цифровой подписи
func verifySignature(pub *rsa.PublicKey, message []byte, signature string) error {
	hash := sha256.New()
	hash.Write(message)
	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash.Sum(nil), signatureBytes)
}

func test() {
	// Генерация ключей
	privKey, pubKey, err := generateKeyPair(2048)
	if err != nil {
		fmt.Println("Ошибка генерации ключей:", err)
		return
	}

	encrypted, err := encrypt(pubKey, []byte("Привет, Россия!")); if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Зашифрованное сообщение:", encrypted)

	decrypted, err := decrypt(privKey, encrypted); if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Расшифрованное сообщение:", decrypted)
}

func in(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func out(path, str string) error {
	err := ioutil.WriteFile(path, []byte(str), 0644) // Записываем в файл
	if err != nil {
		return err
	}

	return nil
}

func get(url string) (string, string, error) {
	// Отправляем GET-запрос
	resp, err := http.Get(url)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close() // Закрываем тело ответа после завершения работы

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		return "", resp.Status, fmt.Errorf("server returned non-200 status: %s", resp.Status)
	}

	// Читаем ответ
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	return string(body), resp.Status, nil
}


func post(url string, data []byte) (string, string, error) {
	// Отправляем POST-запрос
	resp, err := http.Post(url, "text/plain", bytes.NewBuffer(data))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close() // Закрываем тело ответа после завершения работы

	// Читаем ответ
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	return string(body), resp.Status, nil
}

// Принимает строку и возвращает её хеш в виде строки
func sha(message string) string {
	// Создаем новый хеш
	hash := sha256.New()
	
	// Записываем сообщение в хеш
	hash.Write([]byte(message))
	
	// Получаем хеш в виде байтового среза
	hashInBytes := hash.Sum(nil)
	
	// Преобразуем байты в строку в формате hex
	return hex.EncodeToString(hashInBytes)
}

// parseNURL обрабатывает входную строку и возвращает адреса и действие.
func parseNURL(input string) ([]string, string, error) {
    // Удаляем квадратные скобки
    input = strings.Trim(input, "[]")

    // Удаляем лишние символы ']' из строки
    input = strings.ReplaceAll(input, "]", "")

    // Разделяем строку по символу '/'
    parts := strings.Split(input, "/")

    // Проверяем, что есть ровно две части
    if len(parts) != 2 {
        return nil, "", errors.New("недопустимый формат входной строки")
    }

    // Разделяем первую часть по символу ';'
    addresses := strings.Split(parts[0], ";")

    // Возвращаем массив адресов и вторую часть
    return addresses, parts[1], nil
}

// EncodeToBase64 кодирует входную строку в Base64.
func Encode64(input string) string {
    // Преобразуем строку в байтовый массив
    data := []byte(input)
    
    // Кодируем данные в Base64
    encoded := base64.StdEncoding.EncodeToString(data)
    
    return encoded
}

func ensureHTTPProtocol(url string) string {
    if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
        return "http://" + url
    }
    return url
}