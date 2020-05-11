package credentials

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"loggerUtil"
	"sync"
)

const (
	CredentialFileName = "mailCredentials.json"
)

var (
	cred      Credentials
	globalErr error
	doOnce    sync.Once
)

type Credentials struct {
	Email        string
	Password     string
	SmtpServer   string
	TokenAuthKey string
}

func GetCredentials() (Credentials, error) {
	doOnce.Do(fillCredentials)
	if globalErr != nil {
		loggerUtil.Log.Println("Error: FillCredentials from Json file Fail")
		return cred, globalErr
	}
	return cred, nil
}
func fillCredentials() {
	globalErr = errors.New("fillCredentials: Begin Error")
	credentailsFileBytes, err := ioutil.ReadFile(CredentialFileName)
	if err != nil {
		loggerUtil.Log.Println("getCredentials: Error: Opening file: " + CredentialFileName + " " + err.Error())
		globalErr = err
		return
	}

	err = json.Unmarshal(credentailsFileBytes, &cred)
	if err != nil {
		loggerUtil.Log.Println("getCredentials: Error: json Unmarshalling error" + err.Error())
		globalErr = err
		return
	}
	loggerUtil.Log.Println("getCredentials: Reading Credentials: SUCCESS ")
	if cred.Email == "" {
		loggerUtil.Log.Println("getCredentials: Error: Email")
		globalErr = errors.New("Email Credentails empty")
		return
	}
	if cred.Password == "" {
		loggerUtil.Log.Println("getCredentials: Error: Password field Empty")
		globalErr = errors.New("Password Credentails empty")
		return
	}
	if cred.SmtpServer == "" {
		loggerUtil.Log.Println("getCredentials: Error: SMTPServer field Empty")
		globalErr = errors.New("SMTPServer Credentails empty")
		return
	}
	if cred.TokenAuthKey == "" {
		loggerUtil.Log.Println("getCredentials: Error: TokenAuthKey field Empty")
		globalErr = errors.New("TokenAuthKey Credentails empty")
		return
	}
	loggerUtil.Log.Println("getCredentials: All Fields present: SUCCESS ")
	globalErr = nil
	return

}
