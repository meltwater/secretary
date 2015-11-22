package main

import (
	"fmt"
	"log"
	"net/http"
)

func daemon(ip string, port int, privateKeyFile string) {
	publicKey := pemRead("./keys/config-public-key.pem")
	privateKey := pemRead(privateKeyFile)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Expected POST method", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Expected form-urlencoded request body", http.StatusUnsupportedMediaType)
			return
		}

		envelope := r.Form.Get("envelope")
		log.Printf("Received request from %s with envelope %s", r.RemoteAddr, envelope[0:min(len(envelope), 32)])

		if !isEnvelope(envelope) {
			http.Error(w, "Expected envelope=ENC[NACL,...] parameter", http.StatusBadRequest)
			return
		}

		encrypted, err := parseEnvelope(envelope)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to decode envelope (%s)", err), http.StatusBadRequest)
			return
		}

		plaintext, err := decryptBox(publicKey, privateKey, encrypted)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusBadRequest)
			return
		}

		w.Write(plaintext)
	})

	address := fmt.Sprintf("%s:%d", ip, port)
	log.Printf("Daemon listening on %s", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
