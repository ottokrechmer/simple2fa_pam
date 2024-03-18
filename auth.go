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
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

type Body struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	UsePassword bool   `json:"use_password"`
	IP          string `json:"ip"`
	OTP         string `json:"otp"`
}

type responseWithStatus struct {
	Status string `json:"status"`
}

type Config struct {
	ApiKey       			string
	SendPassword 			bool
	Simple2faUrl 			string
	Debug        			bool
	UseOTP       			bool
	UseKeyCloak  			bool
	KeycloakTokenURL 		string
	KeyCloakClientID 		string
	KeyCloakClientSecret 	string
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
func go_authenticate(pamh *C.pam_handle_t) C.int {
	conf := getConfig()

	logger := log.New()
	if conf.Debug {
		file, _ := os.OpenFile("./simple2fa.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		logger.SetLevel(log.DebugLevel)
		logger.Out = file
		defer file.Close()
	}

	logger.Info("Begin new auth request")

	username, err := GetUser(logger, pamh)
	if err != nil {
		logger.WithFields(log.Fields{
			"Username": username,
		}).Debug("Error in getting Username")
		return C.PAM_AUTH_ERR
	}
	password, err := GetPassword(logger, pamh)
	if err != nil {
		logger.WithFields(log.Fields{
			"Username": username,
			"Password": password,
		}).Debug("Error in getting User Password")
		return C.PAM_AUTH_ERR
	}
	rhost, err := GetRemoteHost(logger, pamh)
	if err != nil {
		logger.WithFields(log.Fields{
			"Username":    username,
			"Password":    password,
			"UsePassword": conf.SendPassword,
		}).Debug("Error in getting Remote Host")
		return C.PAM_AUTH_ERR
	}
	var otp string
	if conf.UseOTP {
		otp, err = GetOTP(logger, pamh)
		if err != nil {
			logger.WithFields(log.Fields{
				"Username":    username,
				"Password":    password,
				"UsePassword": conf.SendPassword,
				"IP":          rhost,
			}).Debug("Error in getting OTP")
			return C.PAM_AUTH_ERR
		}
	}

	if conf.UseKeyCloak {
		if !keycloakConnect(logger, conf, username, password) {
			return C.PAM_AUTH_ERR
		}
		conf.SendPassword = false
	}

	logger.Debug("OTP ", otp)

	url := conf.Simple2faUrl + "/api/pamAuth/"
	if !conf.SendPassword {
		password = ""
	}
	body := Body{
		Username:    username,
		Password:    password,
		UsePassword: conf.SendPassword,
		IP:          rhost,
		OTP:         otp,
	}
	logger.WithFields(log.Fields{
		"Username":    body.Username,
		"Password":    body.Password,
		"UsePassword": body.UsePassword,
		"IP":          body.IP,
		"OTP":         body.OTP,
	}).Debug("Send request to API")

	ctx, cancel := context.WithTimeout(context.Background(), 31*time.Second)
	defer cancel()

	responseWithStatus := responseWithStatus{}

	json_data, _ := json.Marshal(&body)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(json_data))
	if err != nil {
		logger.Error("Error making request", err)
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
		logger.Error("Error doing request", err)
		return C.PAM_AUTH_ERR
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.WithFields(log.Fields{
			"Status": resp.Status,
			"Body":   string(json_data),
		}).Error("Authentication failed")
		return C.PAM_AUTH_ERR
	}

	json.NewDecoder(resp.Body).Decode(&responseWithStatus)
	if responseWithStatus.Status == "declined" {
		logger.Info("User declined auth or there is error in login/pass, or no chatId set for user")
		return C.PAM_AUTH_ERR
	}
	logger.Info("Auth success")
	return C.PAM_SUCCESS
}

func keycloakConnect(logger *log.Logger, config *Config, username, password string) bool {

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", config.KeyCloakClientID)
	form.Set("client_secret", config.KeyCloakClientSecret)
	form.Set("username", username)
	form.Set("password", password)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", config.KeycloakTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		logger.WithFields(log.Fields{
			"Username": username,
		}).Error("Error forming request to KeyCloak")
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.WithFields(log.Fields{
			"Username": username,
		}).Error("Error making request to KeyCloak")
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.WithFields(log.Fields{
			"Username": username,
		}).Error("Error reading response from KeyCloak")
		return false
	}

	if resp.StatusCode != http.StatusOK {
		logger.WithFields(log.Fields{
			"Username":   username,
			"respStatus": resp.Status,
			"Body:":      string(body),
		}).Error("Error forming request to KeyCloak")
		return false
	}

	logger.WithFields(log.Fields{
		"Username":   username,
		"respStatus": resp.Status,
		"Body:":      string(body),
	}).Debug("Success response from KeyCloak")
	return true
}
