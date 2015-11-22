package main

import (
	"fmt"
	"log"
	"net/http"
)

func errorResponse(w http.ResponseWriter, r *http.Request, err interface{}, statusCode int) {
	log.Printf("HTTP %d from %s: %s", statusCode, r.RemoteAddr, err)
	http.Error(w, fmt.Sprintf("%s", err), statusCode)
}

func daemonCommand(ip string, port int, crypto Crypto) {
	http.HandleFunc("/v1/decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			errorResponse(w, r, "Expected POST method", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			errorResponse(w, r, "Expected application/x-www-form-urlencoded request body", http.StatusUnsupportedMediaType)
			return
		}

		envelope := r.Form.Get("envelope")
		log.Printf("Received request from %s with envelope %s", r.RemoteAddr, ellipsis(envelope, 64))

		plaintext, err := crypto.Decrypt(envelope)
		if err != nil {
			errorResponse(w, r, err, http.StatusBadRequest)
			return
		}

		// Encrypt secret with public key of client and send it back
		encrypted, err := crypto.Encrypt(plaintext)
		if err != nil {
			errorResponse(w, r, err, http.StatusInternalServerError)
			return
		}

		w.Write([]byte(encrypted))
	})

	address := fmt.Sprintf("%s:%d", ip, port)
	log.Printf("Daemon listening on %s", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
