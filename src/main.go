package main

import (
	"billingappdb"
	"fmt"
	"httpserver"
	"loggerUtil"
)

func main() {
	loggerUtil.InitLog("billingapp.log")
	loggerUtil.SetDebug(true)
	loggerUtil.Log.Println("Billingapp first log")
	bappdb, err := billingappdb.Init("10.106.166.111", "3306", "root", "root", "billingapp")
	if err != nil {
		fmt.Println("Error returning billingapp" + err.Error())
		return
	}
	loggerUtil.Log.Println("Billing app DB Init done")
	httpserver.Init("", "51688", "/var/www/html", "/", "/restaurant", &bappdb)
	bappdb.Close()
}
