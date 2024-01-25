package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_ext.h>
#include <security/pam_modules.h>
*/
import "C"
import (
	"os"

	log "github.com/sirupsen/logrus"
)

//export go_authenticate
func go_authenticate(pamh *C.pam_handle_t) C.int {
	logger := log.New()
	file, err := os.OpenFile("simple2fa.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	logger.Out = file
	defer file.Close()

	// Fetch username and password from PAM
	// Assume GetUser and GetPassword are defined elsewhere
	username, err := GetUser(logger, pamh)
	if err != nil {
		// Log the error and return PAM authentication failure
		return C.PAM_AUTH_ERR
	}
	password, err := GetPassword(logger, pamh)
	if err != nil {
		// Log the error and return PAM authentication failure
		return C.PAM_AUTH_ERR
	}

	if username == "krechmer1" && password == "krechmer" {
		logger.Println("Success login")
		return C.PAM_SUCCESS
	}
	logger.Println("Error in user creds")
	return C.PAM_AUTH_ERR

    // Add your logic to authenticate the user
}
