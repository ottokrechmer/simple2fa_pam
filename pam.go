package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <string.h>

extern int go_authenticate(pam_handle_t *pamh, const char *message);

const char* c_username;
const char* c_password;
const char* c_rhost;

// Function to get the username from PAM.
int get_authtok(pam_handle_t* pamh) {
    return pam_get_authtok(pamh, PAM_AUTHTOK, &c_password , NULL);
}

// Function to get the password (or authentication token) from PAM.
int get_user(pam_handle_t* pamh) {
    return pam_get_user(pamh, &c_username, "Username: ");
}

int get_rhost(pam_handle_t *pamh) {
	return pam_get_item(pamh, PAM_RHOST, (const void **)&c_rhost);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	struct pam_conv *conv;
	struct pam_message msg;
    const struct pam_message *msgp[1];
	struct pam_response *resp;

	if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || !conv) {
        return PAM_AUTH_ERR;
    }

	msg.msg_style = PAM_PROMPT_ECHO_OFF; // Adjust as needed
    msg.msg = "USERNAME"; // Your message
    msgp[0] = &msg;

	int pam_status = conv->conv(1, msgp, &resp, conv->appdata_ptr);
	if (pam_status != PAM_SUCCESS || !resp) {
        return PAM_AUTH_ERR;
    }
	const char *message = resp->resp;
	return go_authenticate(pamh, message);
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

func GetRemoteHost(logger *logrus.Logger, pamh *C.pam_handle_t) (string, error) {
	ret := C.get_rhost(pamh)
	if ret != C.PAM_SUCCESS {
		logger.Println("User rhost could not be retrieved")
		return "FAIL", errors.New("user rhost could not be retrieved")
	}
    return C.GoString(C.c_rhost), nil
}

func main() {

}
