package main

import (
	"crypto/rsa"
	"log"
)

var sk *rsa.PrivateKey
var pk *rsa.PublicKey

func init() {
	sk64, pk64 := "", ""

	sk64, err := in("sk.key"); if err != nil {
		log.Fatal(err)
	}

	pk64, err = in("pk.key"); if err != nil {
		log.Fatal(err)
	}

	sk, err = decodePrivateKey(sk64); if err != nil {
		log.Fatal(err)
	}

	pk, err = decodePublicKey(pk64); if err != nil {
		log.Fatal(err)
	}
}