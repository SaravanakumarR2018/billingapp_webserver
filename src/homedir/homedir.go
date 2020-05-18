package homedir

import (
	"loggerUtil"
	"os"
	"sync"
)

var (
	home   string
	doOnce sync.Once
)

func getHome() {

	homeEnv := `HOME`
	var ok bool
	home, ok = os.LookupEnv(homeEnv)
	if !ok {
		loggerUtil.Log.Println(homeEnv + ": NOT SET: Proceeding with /root as home")
		home = `/root`

	}
	loggerUtil.Debugln("getHome: Home dir " + home)

}

func GetHomeDir() string {
	doOnce.Do(getHome)
	return home
}
