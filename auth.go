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

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

type Body struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	UsePassword bool   `json:"use_password"`
}

type responseWithStatus struct {
	Status string `json:"status"`
}

type Config struct {
	ApiKey       string
	SendPassword bool
	Simple2faUrl string
	Debug        bool
	UseOTP       bool
}

func getConfig() *Config {
	var configFile = "./s2fa_conf.toml"
	_, err := os.Stat(configFile)
	if err != nil {
		log.Println("Config file is missing: config.toml")
	}

	var config Config
	if _, err := toml.DecodeFile(configFile, &config); err != nil {
		log.Println(err)
	}

	return &config
}

//export go_authenticate
func go_authenticate(pamh *C.pam_handle_t, message *C.char) C.int {
	conf := getConfig()

	logger := log.New()
	if conf.Debug {
		file, _ := os.OpenFile("./simple2fa.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		logger.SetLevel(log.DebugLevel)
		logger.Out = file
		defer file.Close()
	}

	logger.Info("Begin New auth request")

	logger.Println("message", C.GoString(message))

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
	rhost, err := GetRemoteHost(logger, pamh)
	if err != nil {
		return C.PAM_AUTH_ERR
	}
	logger.Println("rhost", rhost)

	url := conf.Simple2faUrl + "/api/pamAuth/"
	if !conf.SendPassword {
		password = ""
	}	
	body := Body{
		Username: username,
		Password: password,
		UsePassword: conf.SendPassword,
	}
	logger.WithFields(log.Fields{
		"Username": body.Username,
		"Password": body.Password,
		"UsePassword": body.UsePassword,
	}).Debug("Send request to API")

	ctx, cancel := context.WithTimeout(context.Background(), 31*time.Second)
	defer cancel()

	responseWithStatus := responseWithStatus{}

	json_data, err := json.Marshal(&body)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(json_data))
	if err != nil {
		logger.Println("Error making request", err)
		return C.PAM_AUTH_ERR
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", conf.ApiKey)

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
		logger.Println("User declined auth or there is error in login/pass, or no chatId set for user")
		return C.PAM_AUTH_ERR
	}
	logger.Println("Auth success")
	return C.PAM_SUCCESS
}
