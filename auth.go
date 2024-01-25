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
	"time"

	log "github.com/sirupsen/logrus"
)

type BodyWithPass struct {
	Username	string		`json:"username"`
	Password	string		`json:"password"`
}

type BodyWithoutPass struct {
	Username	string		`json:"username"`
}

type responseWithStatus struct {
	Status string `json:"status"`
}

//export go_authenticate
func go_authenticate(pamh *C.pam_handle_t, argc C.int, pass *C.char, key *C.char) C.int {
	logger := log.New()
	prefix := "simple2fa"
	logger.WithField("prefix", prefix).Info("Begin New auth request")

	if argc != 2 {
		logger.WithField("prefix", prefix).Println("You have to set password policy and api key")
		return C.PAM_AUTH_ERR
	}

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

	var url string
	var body interface{}
	if C.GoString(pass) == "send" {
		url = "https://158.160.57.114/api/authWithPassword/"
		body = BodyWithPass{
			Username: username,
			Password: password,
		}
	} else if C.GoString(pass) == "skip" {
		url = "https://158.160.57.114/api/auth/"
		body = BodyWithoutPass{
			Username: username,
		}
	} else {
		logger.WithField("prefix", prefix).Println(`You have to set password policy "send" or "skip"`)
		return C.PAM_AUTH_ERR
	}

	ctx, cancel := context.WithTimeout(context.Background(), 31*time.Second)
	defer cancel()

	responseWithStatus := responseWithStatus{}

	json_data, err := json.Marshal(&body)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(json_data))
	if err != nil {
		logger.WithField("prefix", prefix).Println("Error making request", err)
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
		logger.WithField("prefix", prefix).Println("Error doing request", err)
		return C.PAM_AUTH_ERR
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Log the error and return PAM authentication failure
		logger.WithField("prefix", prefix).Println("Authentication failed with status:", resp.Status)
		logger.WithField("prefix", prefix).Println("Body:", string(json_data))
		return C.PAM_AUTH_ERR
	}

	err = json.NewDecoder(resp.Body).Decode(&responseWithStatus)
	if responseWithStatus.Status == "declined" {
		logger.WithField("prefix", prefix).Println("User declined auth")
		return C.PAM_AUTH_ERR
	}
	logger.WithField("prefix", prefix).Println("Auth success")
	return C.PAM_SUCCESS
}
