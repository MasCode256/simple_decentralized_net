package main

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Структура для хранения информации о клиенте
type Client struct {
	ID   string `json:"id"`
	Pk 	 string `json:"pk"`
	DecodedPk *rsa.PublicKey
	Conn *websocket.Conn
}

func (this Client) nodemeta() []byte {
	return []byte(this.Pk)
}

// Создаем новый экземпляр upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		if len(clients) < 100 {
			return true // Разрешаем все источники (для тестирования)
		} else {
			return false
		}
	},
}

// Хранение активных клиентов
var clients = make(map[string]*Client)
var mu sync.Mutex // Mutex для защиты доступа к map

// Обработчик для WebSocket соединений
func handleConnection(w http.ResponseWriter, r *http.Request) {
	// Обновляем соединение до WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Ошибка при обновлении соединения:", err)
		return
	}
	defer conn.Close()

	log.Println("Новое соединение.")

	var clientID string

	// Обработка сообщений
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Ошибка при чтении сообщения:", err)
			return
		}
		log.Printf("Получено сообщение: %s\n", msg)

		connection_data := strings.Split(string(msg), ":")

		if len(connection_data) < 2 {
			log.Println("Ошибка при соединении с узлом: недостаточно информации.")
			return
		}

		clientID = connection_data[0]

		// Проверяем, существует ли клиент
		mu.Lock()
		client, exists := clients[clientID]
		mu.Unlock()

		if !exists {
			log.Println("Ошибка: клиент не существует:", clientID + ".", "Список клиентов:", clients)
			return
		}

		pk, err := decodePublicKey(client.Pk)
		if err != nil {
			log.Println(err)
			return
		}

		if err := verifySignature(pk, []byte(client.Pk), connection_data[1]); err == nil {
			if client.Conn == nil {
				client.Conn = conn
				log.Println("Соединение успешно установлено.")
			} else {
				log.Println("Соединение уже было установлено.")
				return
			}
		} else {
			log.Println("Ошибка: подпись неверна:", err)
			return
		}
	}
}


func transmit_to_node(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if q.Has("hpk") && q.Has("msg") {
		if client, exists := clients[q.Get("hpk")]; exists {
			src, err := hex.DecodeString(q.Get("msg")); if err != nil {
				http.Error(w, "decoding error: " + err.Error(), 500)
				log.Println("Ошибка декодирования сообщения:", err)
				return
			}

			err = client.Conn.WriteMessage(1, src); if err != nil {
				http.Error(w, "transmission error: " + err.Error(), 500)
				log.Println("Ошибка передачи сообщения:", err)
				return
			}

			w.Write([]byte("1"))
		}
	} else {
		http.Error(w, "not enough arguments", 400)
		log.Println("Ошибка: недостаточно аргументов.")
		return
	}
}

func new_node(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if !q.Has("pk") {
		http.Error(w, "not enough arguments", 400)
		log.Panicln("Ошибка при создании узла: not enough arguments")
	} else {
		if len(clients) < 100 {
			// Генерируем уникальный идентификатор для клиента
			pk, err := hex.DecodeString(q.Get("pk")); if err != nil {
				log.Println(err)
				return
			}

			dpk, err := decodePublicKey(string(pk)); if err != nil {
				http.Error(w, "pk decoding error", 500)
			}

			clientID := sha(string(pk)) // Можно использовать другой идентификатор, если нужно
			client := &Client{
				Pk:   string(pk),
				DecodedPk: dpk,
				Conn: nil,
			}
	
			if _, exists := clients[clientID]; !exists {
				mu.Lock()
				clients[clientID] = client
				mu.Unlock()

				w.Write([]byte("1"))
				log.Println("Успешное создание узла", clientID)
			} else {
				http.Error(w, "node is already exists", 400)
				log.Println("Ошибка при создании узла: node is already exists")
				return
			}
		} else {
			http.Error(w, "too many clients connected", 500)
			log.Println("Ошибка при создании узла: too many clients connected")
			return
		}
	}
}

func return_node(w http.ResponseWriter, r *http.Request) {
	if _, exists := clients[r.URL.Query().Get("hpk")]; !exists {
		http.NotFound(w, r)
		log.Println("Узел", r.URL.Query().Get("hpk"), "не существует.")
		return
	}

	w.Write(clients[r.URL.Query().Get("hpk")].nodemeta())
}

func main() {
	if len(os.Args) == 1 {
		http.HandleFunc("/ws", handleConnection)
		http.HandleFunc("/get_node", return_node)
		http.HandleFunc("/new_node", new_node)
		http.HandleFunc("/transmit_node", transmit_to_node)
	
		log.Println("Запуск сервера на :8080...")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal("Ошибка при запуске сервера:", err)
		}
	} else if len(os.Args) > 1 {
		if os.Args[1] == "connect" {
			log.Println("Генерация временных ключей...")
			sk, pk, err := generateKeyPair(2048); if err != nil {
				log.Fatal(err)
			}
			pk64 := encodePublicKey(pk)
			hpk := sha(pk64)

			log.Println("Создание узла...")
			err = create_node(os.Args[2], sk, pk); if err != nil {
				log.Fatal(err)
			}

			time.Sleep(200 * time.Millisecond)
			log.Println("Соединение с сервером " + os.Args[2])

			handle_conn(os.Args[2], sk, pk, hpk, func(c *websocket.Conn) {
				// Читаем ответ от сервера
				for {
					_, msg, err := c.ReadMessage()
					if err != nil {
						log.Fatal("Ошибка при чтении сообщения:", err)
						break
					}

					decrypted, err := decrypt(sk, string(msg)); if err != nil {
						log.Fatal("Ошибка при расшифровке сообщения:", err)
					}

					log.Printf("Получено сообщение: %s\n", decrypted)
					time.Sleep(1 * time.Second)
				}
			})
		} else if os.Args[1] == "send_to_node" {
			log.Println("Отправка сообщения клиенту", os.Args[2])

			transmitters, pk_hash, err := parseNURL(os.Args[2]); if err != nil {
				log.Fatal(err)
			}

			for i, v := range transmitters {
				transmitter_meta := strings.Split(v, "#")
				log.Println("Попытка", i, ". Передатчик: " + v)

				if len(transmitter_meta) > 1 && len(transmitter_meta[0]) > 1 {
					log.Println("Сервер имеет защиту hsk")
				} else {
					fmt.Println("Сервер не имеет защиты hsk.")
					log.Println("Получение узла...")
				
					// Убедитесь, что URL имеет корректный протокол
					nodeURL := ensureHTTPProtocol("http://" + transmitter_meta[1] + "/get_node?hpk=" + pk_hash)
					body, stat, err := get(nodeURL)
					if err != nil {
						log.Fatal(stat, ":", err)
					}
				
					log.Println("Открытый ключ узла:", body)
				
					if sha(body) != pk_hash {
						log.Fatal("Хэши открытого ключа не совпадают.")
					}
				
					pk, err := decodePublicKey(body)
					if err != nil {
						log.Fatal(err)
					}
				
					msg, err := encrypt(pk, []byte(os.Args[3]))
					if err != nil {
						log.Fatal(err)
					}
				
					// Убедитесь, что URL имеет корректный протокол
					transmitURL := ensureHTTPProtocol("http://" + transmitter_meta[1] + "/transmit_node?hpk=" + pk_hash + "&msg=" + hex.EncodeToString([]byte(msg)))
					body, stat, err = get(transmitURL)
					if err != nil {
						log.Fatal("Ошибка отправки сообщения (", transmitURL, "):", stat, ":", err)
					}
				
					log.Println("Ответ от узла:", body)
				}
				
			}

			body, stat, err := get(os.Args[2]); if err != nil {
				log.Fatal(err)
			}

			log.Println(stat, ":", body)
		} else if os.Args[1] == "generate_keys" {
			log.Println("Генерация ключей...")

			sk, pk, err := generateKeyPair(2048); if err != nil {
				log.Fatal("Ошибка генерации ключей:", err)
			}

			sk64 := encodePrivateKey(sk)
			pk64 := encodePublicKey(pk)

			if len(os.Args) > 3 {
				err = out(os.Args[2], sk64); if err != nil {
					log.Fatal("Ошибка при записи секретного ключа в файл:", err)
				}
	
				err = out(os.Args[3], pk64); if err != nil {
					log.Fatal("Ошибка при записи открытого ключа в файл:", err)
				}
			} else if len(os.Args) > 1 {
				err = out("sk.key", sk64); if err != nil {
					log.Fatal("Ошибка при записи секретного ключа в файл:", err)
				}
	
				err = out("pk.key", pk64); if err != nil {
					log.Fatal("Ошибка при записи открытого ключа в файл:", err)
				}
			} else {
				log.Fatal("Ошибка командной строки.")
			}
		}
	}
}
