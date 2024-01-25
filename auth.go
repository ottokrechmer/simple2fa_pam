package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_ext.h>
#include <security/pam_modules.h>
*/
import "C"
import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

type Body struct {
	Username	string		`json:"username"`
	Password	string		`json:"password"`
}

type responseWithStatus struct {
	Status string `json:"status"`
}

//export go_authenticate
func go_authenticate(pamh *C.pam_handle_t, argc C.int, pass *C.char, key *C.char) C.int {
	logger := log.New()
	file, err := os.OpenFile("simple2fa.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	logger.Out = file
	defer file.Close()
	logger.Println("===========================================")

	// Fetch username and password from PAM
	// Assume GetUser and GetPassword are defined elsewhere
	username, err := GetUser(logger, pamh)
	if err != nil {
		return C.PAM_AUTH_ERR
	}
	password, err := GetPassword(logger, pamh)
	if err != nil {
		return C.PAM_AUTH_ERR
	}

	ctx, cancel := context.WithTimeout(context.Background(), 31*time.Second)
	defer cancel()

	body := Body{
		Username: username,
		Password: password,
	}
	responseWithStatus := responseWithStatus{}

	json_data, err := json.Marshal(&body)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://158.160.57.114/api/authWithPassword/", bytes.NewBuffer(json_data))
	if err != nil {
		logger.Println("Error making request", err)
		return C.PAM_AUTH_ERR
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", C.GoString(key))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Println("Error doing request", err)
		return C.PAM_AUTH_ERR
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Log the error and return PAM authentication failure
		logger.Println("Authentication failed with status:", resp.Status)
		logger.Println("Body:", string(json_data))
		return C.PAM_AUTH_ERR
	}

	err = json.NewDecoder(resp.Body).Decode(&responseWithStatus)
	if responseWithStatus.Status == "declined" {
		return C.PAM_AUTH_ERR
	}
	return C.PAM_SUCCESS
}
