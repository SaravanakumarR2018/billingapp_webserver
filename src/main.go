package main

import (
	"billingappdb"
	"credentials"
	"cryptography"
	"fmt"
	"httpserver"
	"loggerUtil"
	"os"
)

func main() {
	loggerUtil.InitLog("billingapp.log")
	loggerUtil.SetDebug(true)
	loggerUtil.Log.Println("Billingapp first log")
	_, err := credentials.GetCredentials()
	if err != nil {
		loggerUtil.Log.Println("main: Error getting Credentials from json file" + credentials.CredentialFileName + err.Error())
		fmt.Println("main: Error getting Credentials from json file" + credentials.CredentialFileName + err.Error())
		return
	}

	testing_env := `TESTBILLINGAPP`
	_, ok := os.LookupEnv(testing_env)
	if !ok {
		loggerUtil.Log.Println(testing_env + ": NOT SET: Proceeding with application")
	} else {
		loggerUtil.Log.Println(testing_env + ":  SET: Executing testcases for the application")
		main_test()
		return
	}

	dbhost_env := "DB_BILLINGAPP_HOST"
	billingappdb_host, ok := os.LookupEnv(dbhost_env)
	if !ok {
		loggerUtil.Log.Println("NOT SET: DB_BILLINGAPP_HOST environmental variable: exit")
		fmt.Println("NOT SET: DB_BILLINGAPP_HOST environmental variable: exit")
		return
	}
	dbport_env := "DB_BILLINGAPP_PORT"
	billingappdb_port, ok := os.LookupEnv(dbport_env)
	if !ok {
		loggerUtil.Log.Println("NOT SET: DB_BILLINGAPP_PORT environmental variable: Default value: 3306 taken")
		billingappdb_port = "3306"
	}
	dbuser_env := "DB_BILLINGAPP_USER"
	billingappdb_user, ok := os.LookupEnv(dbuser_env)
	if !ok {
		loggerUtil.Log.Println("NOT SET: DB_BILLINGAPP_USER environmental variable: Default value: root taken")
		billingappdb_user = "root"
	}
	dbpsw_env := "DB_BILLINGAPP_PASSWORD"
	billingappdb_psw, ok := os.LookupEnv(dbpsw_env)
	if !ok {
		loggerUtil.Log.Println("NOT SET: DB_BILLINGAPP_PASSWORD environmental variable:")
		billingappdb_psw = "root"
	}

	httpserverip_env := "HTTP_BILLINGAPP_IP"
	billingapphttp_ip, ok := os.LookupEnv(httpserverip_env)
	if !ok {
		loggerUtil.Log.Println("NOT SET: HTTP_BILLINGAPP_IP environmental variable: Default empty taken")
		billingapphttp_ip = ""
	}
	httpserverport_env := "HTTP_BILLINGAPP_PORT"
	billingapphttp_port, ok := os.LookupEnv(httpserverport_env)
	if !ok {
		loggerUtil.Log.Println("NOT SET: HTTP_BILLINGAPP_PORT environmental variable: Default 80 taken")
		billingapphttp_port = "80"
	}
	httpserverdir_env := "HTTP_BILLINGAPP_DIR"
	billingapphttp_dir, ok := os.LookupEnv(httpserverdir_env)
	if !ok {
		loggerUtil.Log.Println("NOT SET: HTTP_BILLINGAPP_DIR environmental variable: Default /var/www/html taken")
		billingapphttp_dir = "/var/www/html"
	}

	bappdb, err := billingappdb.Init(billingappdb_host, billingappdb_port, billingappdb_user, billingappdb_psw, "billingapp")
	if err != nil {
		fmt.Println("Error returning billingapp" + err.Error())
		return
	}
	loggerUtil.Log.Println("Billing app DB Init done")
	httpserver.Init(billingapphttp_ip, billingapphttp_port, billingapphttp_dir, "/", "/restaurant", &bappdb)
	bappdb.Close()

}
func main_test() {
	fmt.Println("Entering main_test")
	crypt, err := cryptography.Encrypt("saravana.k.r@gmail.com")
	if err != nil {
		fmt.Println("main_test: Encrypt email " + "saravana.k.r@gmail.com" + crypt)
	}
	fmt.Println("cipher text " + crypt)
	email, err := cryptography.Decrypt(crypt)
	if err != nil {
		fmt.Println("main_test: Decrypt cipher " + crypt + email)
	}
	fmt.Println("Decrypted email " + email)
}
