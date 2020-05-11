package newpasswordsender

import (
	"credentials"
	"loggerUtil"
	"strings"
)

func SendNewPassword(mail, password string) error {
	loggerUtil.Log.Println("Sending new Password to " + mail)
	go sendRoutinePassword(mail, password)
	return nil
}
func sendRoutinePassword(mail, password string) error {

	// Try opening the file and load the variables
	loggerUtil.Log.Println("sendRoutinePassword: Mail: Password for " + mail)
	credentials, err := credentials.GetCredentials()
	if err != nil {
		loggerUtil.Log.Println("sendRoutinePassword: Error: getting smtp credentials")
		return err
	}

	sender := NewSender(credentials.Email, credentials.Password, credentials.SmtpServer)

	//The receiver needs to be in slice as the receive supports multiple receiver
	Receiver := []string{mail}

	Subject := "Free Billing App: New Password"
	message := `
	<!DOCTYPE HTML PULBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
	<html>
	<head>
	<meta http-equiv="content-type" content="text/html"; charset=ISO-8859-1">
	</head>
	<body>Your New Password: 
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
