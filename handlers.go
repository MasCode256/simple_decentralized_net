package main

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"log"
	"os"

	"github.com/gorilla/websocket"
)

func create_node(addr string, sk *rsa.PrivateKey, pk *rsa.PublicKey) error {
	pk64 := encodePublicKey(pk)
	result, _, err := get("http://" + addr + "/new_node?pk=" + hex.EncodeToString([]byte(pk64))); if err != nil {
		return err
	}
	if result != "1" {
		return errors.New("result not equal 1: " + result)
	}

	return nil
}

func handle_conn(addr string, sk *rsa.PrivateKey, pk *rsa.PublicKey, hpk string, handler func(*websocket.Conn)) error {
	pk64 := encodePublicKey(pk)

	// Устанавливаем соединение с сервером
	url := "ws://" + os.Args[2] + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Println("Соединение успешно установлено. Адрес: [#" + os.Args[2] + "]/" + hpk)

	sign, err := createSignature(sk, []byte(pk64)); if err != nil {
		return err
	}

	err = conn.WriteMessage(1, []byte(hpk + ":" + sign)); if err != nil {
		return err
	}

	handler(conn)
	return nil
}