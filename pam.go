package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <string.h>

extern int go_authenticate(pam_handle_t *pamh, int argc, const char *pass, const char *key);

const char* c_username;
const char* c_password;

// Function to get the username from PAM.
int get_authtok(pam_handle_t* pamh) {
    return pam_get_authtok(pamh, PAM_AUTHTOK, &c_password , NULL);
}

// Function to get the password (or authentication token) from PAM.
int get_user(pam_handle_t* pamh) {
    return pam_get_user(pamh, &c_username, "Username: ");
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return go_authenticate(pamh, argc, argv[0], argv[1]);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

*/
import "C"

import (
	"errors"
	
	"github.com/sirupsen/logrus"
)


func GetUser(logger *logrus.Logger, pamh *C.pam_handle_t) (string, error) {
	ret := C.get_user(pamh)
	if ret != C.PAM_SUCCESS {
		logger.Println("Username could not be retrieved")
		return "", errors.New("username could not be retrieved")
	}
	return C.GoString(C.c_username), nil
}

func GetPassword(logger *logrus.Logger, pamh *C.pam_handle_t) (string, error) {
	ret := C.get_authtok(pamh)
	if ret != C.PAM_SUCCESS {
		logger.Println("User password could not be retrieved")
		return "", errors.New("user password could not be retrieved")
	}
	return C.GoString(C.c_password), nil
}

func main() {

}