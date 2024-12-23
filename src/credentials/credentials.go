package credentials

import (
	"encoding/json"
	"errors"
	"homedir"
	"io/ioutil"
	"log"
	"loggerUtil"
	"os"
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
	Domains      []string
}

func GetCredentials() (Credentials, error) {
	doOnce.Do(fillCredentials)
	if globalErr != nil {
		loggerUtil.Log.Println("Error: FillCredentials from Json file Fail")
		return cred, globalErr
	}
	return cred, nil
}
func GetCredentialsDir() string {
	credDir := homedir.GetHomeDir() + `/credentials/`
	loggerUtil.Debugln("GetCredentialsDir: Credentials Dir: " + credDir)
	return credDir

}
func fillCredentials() {
	globalErr = errors.New("fillCredentials: Begin Error")
	credentialdir := GetCredentialsDir()
	credentailsFileBytes, err := ioutil.ReadFile(credentialdir + CredentialFileName)
	if err != nil {
		loggerUtil.Log.Println("getCredentials: Error: Opening file: " + CredentialFileName + " " + err.Error())
		globalErr = err
		return
	}
	loggerUtil.Log.Println("fillCredentials: Credential File " + credentialdir + CredentialFileName)

	dummyFileCheckPermission := credentialdir + "dummyFile.txt"
	loggerUtil.Log.Println("fillCredentials: Check file exists: " + dummyFileCheckPermission)
	_, err = os.Stat(dummyFileCheckPermission)
	if err == nil {
		loggerUtil.Log.Println("fillCredentials: File exists:removing file " + dummyFileCheckPermission)
		err = os.Remove(dummyFileCheckPermission)
		if err != nil {
			loggerUtil.Log.Println("Write permission denied: Cannot delete file " + dummyFileCheckPermission + " " + err.Error())
			log.Fatalln("Write permission denied: Cannot delete file " + dummyFileCheckPermission + " " + err.Error())
		}
	} else {
		loggerUtil.Log.Println("fillCredentials: File does not exists: " + dummyFileCheckPermission)
	}
	loggerUtil.Log.Println("fillCredentials: creating file " + dummyFileCheckPermission)
	file, err := os.Create(dummyFileCheckPermission)
	file.Write([]byte("Checking permissions"))
	if err != nil {
		loggerUtil.Log.Println("Write Permission: Not available " + credentialdir + " " + err.Error())
		log.Fatal("Write Permission: Not available " + credentialdir + " " + err.Error())
	}
	file.Close()
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
	if len(cred.Domains) == 0 {
		loggerUtil.Log.Println("getCredentials: Error: Domain field Empty")
		globalErr = errors.New("Domain names within Credential file empty")
		return
	}
	loggerUtil.Log.Println("getCredentials: All Fields present: SUCCESS ")
	globalErr = nil
	return

}
