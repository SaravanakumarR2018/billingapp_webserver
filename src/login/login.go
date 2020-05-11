package login

import (
	"billingappdb"
	"cryptography"
	"loggerUtil"
	"math/rand"
	"net/http"
	"newpasswordsender"
	"strconv"
	"time"
)

func ChangePassword(w http.ResponseWriter, req *http.Request, billdb *billingappdb.BillAppDB) {
	email := req.Header.Get("Email")
	password := req.Header.Get("Password")
	var NO_PASSWORD string
	if password == NO_PASSWORD {
		loggerUtil.Log.Println("ResetPassword: Password not present in header for the requested URL", req.URL.Path, password)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Password not present in header for the requested URL"))
		return
	}
	err := billdb.ResetPassword(email, password)
	if err != nil {
		loggerUtil.Log.Println("ResetPassword: Failure to reset password for Email: " + email + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("ResetPassword: Failure to reset password for Email:" + email + ": " + err.Error()))
		return
	}
	token, err := cryptography.Encrypt(email)
	if err != nil {
		loggerUtil.Log.Println("ChangePassword: acquiring token for login reqest Fail")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("ResetPassword: acquiring token for login reqest Fail"))
		return
	}
	w.Header().Set("token", token)
	w.WriteHeader(http.StatusOK)
	return
}
func ForgotPassword(w http.ResponseWriter, req *http.Request, billdb *billingappdb.BillAppDB) {
	email := req.Header.Get("Email")
	password := generateNewPassword()
	err := billdb.ResetPassword(email, password)
	if err != nil {
		loggerUtil.Log.Println("ForgotPassword: Failure to change password for Email: " + email + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("ForgotPassword: Failure to change password for Email:" + email + ": " + err.Error()))
		return
	}
	err = newpasswordsender.SendNewPassword(email, password)
	if err != nil {
		loggerUtil.Log.Println("ForgotPassword: FAILURE: Send Email of new Password for " + email)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("ForgotPassword: Failure to send password to Email:" + email + ": " + err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	return

}

func ProcessLoginGetMethod(w http.ResponseWriter, req *http.Request, billdb *billingappdb.BillAppDB) {
	email := req.Header.Get("Email")
	password := req.Header.Get("Password")
	var NO_PASSWORD string
	if password == NO_PASSWORD {
		loggerUtil.Log.Println("processLoginGetMethod: Password not present in header for the requested URL", req.URL.Path, password)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Password not present in header for the requested URL"))
		return
	}
	isEmailValid, err := billdb.VerifyEmailAndPassword(email, password)
	if err != nil {
		loggerUtil.Log.Println("processLoginGetMethod: Error retrieving " + email + " " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error retrieving " + email))
		return
	}
	loggerUtil.Debugln("ProcessLoginGetMethod: Validity of email " + email + " is " + strconv.FormatBool(isEmailValid))
	if !isEmailValid {
		loggerUtil.Log.Println("processLoginGetMethod: Authentication failure" + email)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Authentication Failure: Email: " + email))
		return
	}
	token, err := cryptography.Encrypt(email)
	if err != nil {
		loggerUtil.Log.Println("processLoginGetMethod: acquiring token for login reqest Fail")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("acquiring token for login reqest Fail"))
		return
	}
	w.Header().Set("token", token)
	w.WriteHeader(http.StatusOK)

}

func random(min, max int) int {
	return rand.Intn(max-min) + min
}

func generateNewPassword() string {
	MIN := 0
	MAX := 94
	SEED := time.Now().Unix()
	var LENGTH int64 = 8
	var newPassword string = ""

	rand.Seed(SEED)
	startChar := "!"
	var i int64 = 1
	for {
		myRand := random(MIN, MAX)
		newChar := string(startChar[0] + byte(myRand))
		newPassword = newPassword + newChar
		if i == LENGTH {
			break
		}
		i++
	}
	return newPassword
}
