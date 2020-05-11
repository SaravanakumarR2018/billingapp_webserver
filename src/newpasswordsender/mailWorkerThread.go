package newpasswordsender

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"loggerUtil"
	"strings"
	"credentials"
)




var (
	credentials MailCredentils
)

func SendNewPassword(mail, password string) error {
	loggerUtil.Log.Println("Sending new Password to " + mail)
	go sendRoutinePassword(mail, password)
	return nil
}
func sendRoutinePassword(mail, password string) error {

	// Try opening the file and load the variables
	loggerUtil.Log.Println("sendRoutinePassword: Mail: Password for " + mail)
	credentials, err = credentials.GetCredentials()
	if err != nil {
		loggerUtil.Log.Println("sendRoutinePassword: Error: getting smtp credentials")
		return err
	}

	sender := NewSender(credentials.Email, credentials.Password, credentials.SmtpServer)

	//The receiver needs to be in slice as the receive supports multiple receiver
	Receiver := []string{mail}

	Subject := "Free Billing App OTP"
	message := `
	<!DOCTYPE HTML PULBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
	<html>
	<head>
	<meta http-equiv="content-type" content="text/html"; charset=ISO-8859-1">
	</head>
	<body>Your One Time Password: 
              REPLACE_STRING 
	</body>
	</html>
	`
	message = strings.Replace(message, "REPLACE_STRING", password, 1)
	loggerUtil.Log.Println("New Password ready to be sent ")
	bodyMessage := sender.WriteHTMLEmail(Receiver, Subject, message)

	err = sender.SendMail(Receiver, Subject, bodyMessage)
	if err != nil {
		loggerUtil.Log.Println("Error: Sending New Password Email to " + mail)
		return err
	}
	loggerUtil.Log.Println("New Password sent: SUCCESS ")
	return nil
}

func processLoginGetMethod(w http.ResponseWriter, req *http.Request) {
	err := validateAndConvertEmailAndAuthorize()
	if err != nil {
		loggerUtil.Log.Println("processLoginGetMethod: error: Validating and converting Email: " + err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	email := req.Header.Get("Email")
	var NO_EMAIL string
	if email == NO_EMAIL {
		loggerUtil.Log.Println("processLoginGetMethod: Email not present in header for the requested URL", req.URL.Path, email)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	password := req.Header.Get("Password")
	var NO_PASSWORD string
	if restaurant_name == NO_PASSWORD {
		loggerUtil.Log.Println("processLoginGetMethod: Password not present in header for the requested URL", req.URL.Path, password)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err := http_current_server.billdb.verifyEmailAndPassword(email, password)
	if err != nil {
		loggerUtil.Log.Println("processLoginGetMethod: Authentication failure" + email + " " + err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token := getToken(email)
	w.Header.Set("token", token)
	w.WriteHeader(http.StatusOK)

}
