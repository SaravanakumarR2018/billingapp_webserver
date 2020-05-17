package httpserver

import (
	"billingappdb"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"loggerUtil"
	"login"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"

	"github.com/golang/gddo/httputil/header"
)

const (
	Email               string = "^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	emailHeader                = "Email"
	authorizationHeader        = "Authorization"
	ContentType                = "Content-type"
	RestaurantName             = "RestaurantName"
)

var (
	rxEmail = regexp.MustCompile(Email)
)

type malformedRequest struct {
	status int
	msg    string
}

func (mr *malformedRequest) Error() string {
	return mr.msg
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {

	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if !strings.Contains(value, "application/json") {
			msg := "Content-Type header is not application/json"
			return &malformedRequest{status: http.StatusUnsupportedMediaType, msg: msg}
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&dst)
	if err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError

		switch {
		case errors.As(err, &syntaxError):
			msg := fmt.Sprintf("Request body contains badly-formed JSON (at position %d)", syntaxError.Offset)
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}

		case errors.Is(err, io.ErrUnexpectedEOF):
			msg := fmt.Sprintf("Request body contains badly-formed JSON")
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}

		case errors.As(err, &unmarshalTypeError):
			msg := fmt.Sprintf("Request body contains an invalid value for the %q field (at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}

		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			msg := fmt.Sprintf("Request body contains unknown field %s", fieldName)
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}

		case errors.Is(err, io.EOF):
			msg := "Request body must not be empty"
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}

		case err.Error() == "http: request body too large":
			msg := "Request body must not be larger than 1MB"
			return &malformedRequest{status: http.StatusRequestEntityTooLarge, msg: msg}

		default:
			return err
		}
	}

	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		msg := "Request body must only contain a single JSON object"
		return &malformedRequest{status: http.StatusBadRequest, msg: msg}
	}

	return nil
}

type FileSystem struct {
	fs http.FileSystem
}
type httpServer struct {
	ip                   string
	port                 string
	httpsPort            string
	fs_directory         string
	directory_url        string
	RestaurantUrl        string
	billdb               *billingappdb.BillAppDB
	orders_url           string
	restaurantlist_url   string
	addnewrestaurant_url string
	loginHandlerUrl      string
	resetPasswordUrl     string
	forgotPasswordUrl    string
	signupUrl            string
	debugUrl             string
}

var http_current_server httpServer

func Init(ip, port, httpsPort, fs_directory, directory_url, RestaurantUrl string, billdb *billingappdb.BillAppDB) {
	http_current_server = httpServer{
		ip:                   ip,
		port:                 port,
		httpsPort:            httpsPort,
		fs_directory:         fs_directory,
		directory_url:        directory_url,
		RestaurantUrl:        RestaurantUrl,
		billdb:               billdb,
		orders_url:           RestaurantUrl + `/orders`,
		restaurantlist_url:   RestaurantUrl + `/restaurantlist`,
		addnewrestaurant_url: RestaurantUrl + `/addnewrestaurant`,
		loginHandlerUrl:      RestaurantUrl + `/login`,
		resetPasswordUrl:     RestaurantUrl + `/resetPassword`,
		forgotPasswordUrl:    RestaurantUrl + `/forgotPassword`,
		signupUrl:            RestaurantUrl + `/signup`,
		debugUrl:             RestaurantUrl + `/debug`,
	}

	new_port := flag.String("p", port, "port to serve on")
	new_https_port := flag.String("sp", httpsPort, "HTTPs port to serve on")
	directory := flag.String("d", fs_directory, "the directory of static file to host")
	flag.Parse()
	fileServer := http.FileServer(FileSystem{http.Dir(*directory)})
	http.Handle(directory_url, http.StripPrefix(strings.TrimRight(directory_url, directory_url), fileServer))
	orders_url := http_current_server.orders_url
	restaurantlist_url := http_current_server.restaurantlist_url
	addnewrestaurant_url := http_current_server.addnewrestaurant_url
	loginHandlerUrl := http_current_server.loginHandlerUrl
	resetPasswordUrl := http_current_server.resetPasswordUrl
	forgotPasswordUrl := http_current_server.forgotPasswordUrl
	signUpUrl := http_current_server.signupUrl
	debugUrl := http_current_server.debugUrl
	loggerUtil.Debugln("Orders ", orders_url, restaurantlist_url, addnewrestaurant_url, loginHandler,
		resetPasswordUrl, forgotPasswordUrl, signUpUrl)
	http.HandleFunc(orders_url, umbrellaHandler)
	http.HandleFunc(restaurantlist_url, umbrellaHandler)
	http.HandleFunc(addnewrestaurant_url, umbrellaHandler)
	http.HandleFunc(loginHandlerUrl, umbrellaHandler)
	http.HandleFunc(resetPasswordUrl, umbrellaHandler)
	http.HandleFunc(forgotPasswordUrl, umbrellaHandler)
	http.HandleFunc(signUpUrl, umbrellaHandler)
	http.HandleFunc(debugUrl, umbrellaHandler)

	keypemFile, certpemFile := getCertificateFiles()
	if keypemFile == "" || certpemFile == "" {
		loggerUtil.Log.Fatal("Certificate files missing: Exiting")
		log.Fatal("Certificate files missing: Exiting")
	}
	go HTTPServer(directory, new_port)
	fmt.Printf("Serving %s on HTTPs port: %s\n", *directory, *new_https_port)
	loggerUtil.Log.Printf("Serving %s on HTTPs port: %s\n", *directory, *new_https_port)
	log.Fatal(http.ListenAndServeTLS(":"+*new_https_port, certpemFile, keypemFile, nil))
}

func redirect(w http.ResponseWriter, req *http.Request) {
	target := "https://" + req.Host + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}
	loggerUtil.Log.Printf("redirect to: %s\n", target)
	http.Redirect(w, req, target,
		// see comments below and consider the codes 308, 302, or 301
		http.StatusPermanentRedirect)
}

func HTTPServer(directory, new_port *string) {
	fmt.Printf("Serving %s on HTTP port: %s\n", *directory, *new_port)
	loggerUtil.Log.Printf("Serving %s on HTTP port: %s\n", *directory, *new_port)
	log.Fatal(http.ListenAndServe(":"+*new_port, http.HandlerFunc(redirect)))
}
func umbrellaHandler(w http.ResponseWriter, req *http.Request) {

	orders_url := http_current_server.orders_url
	restaurantlist_url := http_current_server.restaurantlist_url
	addnewrestaurant_url := http_current_server.addnewrestaurant_url
	loginHandlerUrl := http_current_server.loginHandlerUrl
	resetPasswordUrl := http_current_server.resetPasswordUrl
	forgotPasswordUrl := http_current_server.forgotPasswordUrl
	signUpUrl := http_current_server.signupUrl
	debugUrl := http_current_server.debugUrl
	if loggerUtil.GetDebug() {
		httpHandleDumpRequest(req)
	}
	add_CORS_headers(w, req)
	if req.Method == http.MethodOptions {
		loggerUtil.Debugln("umbrellaHandler: Processing OPTIONS method for CORS", req.URL.Path)
		processOptionsMethod(w, req)
		return
	}
	c_bill_ptr, err := getCurrentBillEntries(w, req)
	if err != nil {
		loggerUtil.Log.Println("umbrellaHandler: Error Converting body to c_bill")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Malformed Request: should be a json"))
		return
	}
	loggerUtil.Debugln(c_bill_ptr)
	err = validateEmail(w, req, c_bill_ptr)
	if err != nil {
		loggerUtil.Log.Println("umbrellaHandler: Error: Validating and Converting Email fields " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid Email address " + err.Error()))
		return
	}

	if req.URL.Path == loginHandlerUrl {
		loginHandler(w, req)
		return
	}

	if req.URL.Path == forgotPasswordUrl {
		forgotPassword_handler(w, req)
		return
	}
	if req.URL.Path == signUpUrl {
		signup_handler(w, req)
		return
	}

	err = authorizeRequest(w, req, c_bill_ptr, http_current_server.billdb)
	if err != nil {
		loggerUtil.Log.Println("umbrellaHandler: Error: Request Not Authorized: " + err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid Session and User"))
		return
	}

	if req.URL.Path == orders_url {
		orders_handler(w, req, c_bill_ptr)
		return
	} else if req.URL.Path == restaurantlist_url {
		restaurantlist_handler(w, req)
		return
	} else if req.URL.Path == addnewrestaurant_url {
		addnewrestaurant_handler(w, req, c_bill_ptr)
		return
	} else if req.URL.Path == resetPasswordUrl {
		resetPassword_handler(w, req)
		return
	} else if req.URL.Path == debugUrl {
		debug_handler(w, req)
		return
	} else {
		loggerUtil.Debugln("Bad request url ", req.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
	}
}
func resetPassword_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("resetPassword_handler: Processing GET method", req.URL.Path)
		login.ChangePassword(w, req, http_current_server.billdb)
	} else {
		loggerUtil.Debugln("resetPassword_handler: Bad Request ", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func forgotPassword_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("forgotPassword_handler: Processing GET method", req.URL.Path)
		login.ForgotPassword(w, req, http_current_server.billdb)
	} else {
		loggerUtil.Debugln("forgotPassword_handler: Bad Request ", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}
func signup_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("signup_handler: Processing GET method", req.URL.Path)
		login.SignUp(w, req, http_current_server.billdb)
	} else {
		loggerUtil.Debugln("signup_handler: Bad Request ", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func loginHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("loginHandler: Processing GET method", req.URL.Path)
		login.ProcessLoginGetMethod(w, req, http_current_server.billdb)
	} else {
		loggerUtil.Debugln("loginHandler: Bad Request ", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}

}
func debug_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("debug_handler: Processing GET method", req.URL.Path)
		debugGetMethod(w, req)
	} else {
		loggerUtil.Debugln("debug_handler: Bad Request", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}
func addnewrestaurant_handler(w http.ResponseWriter, req *http.Request, c_bill_ptr *(billingappdb.Bill)) {
	if req.Method == http.MethodPost {
		loggerUtil.Debugln("addnewrestaurant_handler: Processing POST method", req.URL.Path)
		processAddNewRestaurantMethod(w, req, c_bill_ptr)
	} else {
		loggerUtil.Debugln("addnewrestaurant_handler: Bad Request", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func processOptionsMethod(w http.ResponseWriter, req *http.Request) {
	loggerUtil.Debugln("processOptionsMethod: Returning HTTP Status OK")
	w.WriteHeader(http.StatusOK)
}
func add_CORS_headers(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
}

func restaurantlist_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("restaurantlist_handler: Processing GET method", req.URL.Path)
		processRstrntListGETMethod(w, req)
	} else {
		loggerUtil.Debugln("restaurantlist_handler: Bad Request", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func orders_handler(w http.ResponseWriter, req *http.Request, c_bill_ptr *(billingappdb.Bill)) {
	if req.Method == http.MethodPost {
		loggerUtil.Debugln("orders_handler: Processing POST method", req.URL.Path)
		processPOSTMethod(w, req, c_bill_ptr)
	} else if req.Method == http.MethodGet {
		loggerUtil.Debugln("orders_handler: Processing GET method", req.URL.Path)
		processGETMethod(w, req)
	} else {
		loggerUtil.Debugln("orders_handler: Bad Request", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}
func processAddNewRestaurantMethod(w http.ResponseWriter, req *http.Request, c_bill_ptr *(billingappdb.Bill)) {
	content_type := req.Header.Get(ContentType)
	if !strings.Contains(content_type, `application/json`) {
		loggerUtil.Log.Println("Error: processAddNewRestaurantMethod: POST: The post operation should contain json data")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	restaurant_id, err := http_current_server.billdb.Get_id_and_update_restaurant_db_tables(c_bill_ptr)
	if err != nil {
		loggerUtil.Log.Println("Error: processAddNewRestaurantMethod: Cannot add new restaiurant", c_bill_ptr.Email,
			c_bill_ptr.RestaurantName)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	loggerUtil.Debugln("Restaurant id " + string(restaurant_id) + " " + c_bill_ptr.Email + " " + c_bill_ptr.RestaurantName)
	w.WriteHeader(http.StatusOK)
	return

}
func processPOSTMethod(w http.ResponseWriter, req *http.Request, c_bill_ptr *(billingappdb.Bill)) {
	content_type := req.Header.Get(ContentType)
	if !strings.Contains(content_type, `application/json`) {
		loggerUtil.Log.Println("Error: POST: The post operation should contain json data")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	current_bill, err := json.Marshal(*c_bill_ptr)
	if err != nil {
		loggerUtil.Log.Println("Error: POST: Converting Request json from struct to byte array", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = http_current_server.billdb.Insert(current_bill)
	if err != nil {
		loggerUtil.Log.Println("Inserting Bill Into DB failed: ", err.Error(), string(current_bill))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	return
}
func processRstrntListGETMethod(w http.ResponseWriter, req *http.Request) {
	loggerUtil.Debugln("Correct Request URL ", req.URL.Path)
	email := req.Header.Get(emailHeader)
	var NO_EMAIL string
	if email == NO_EMAIL {
		loggerUtil.Log.Println("Email not present in header for the requested URL", req.URL.Path, email)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var c_bill billingappdb.Bill
	c_bill.Email = email

	email_details, err := json.Marshal(c_bill)
	if err != nil {
		loggerUtil.Log.Println("Error: Converting Request json from struct to byte array", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	restaurant_list, err := http_current_server.billdb.GetRestaurantList(email_details)
	if err != nil {
		loggerUtil.Log.Println("Error: Converting Email to Restaurant List")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(restaurant_list)
	return

}

func processGETMethod(w http.ResponseWriter, req *http.Request) {

	loggerUtil.Debugln("Correct Request URL ", req.URL.Path)

	email := req.Header.Get(emailHeader)
	var NO_EMAIL string
	if email == NO_EMAIL {
		loggerUtil.Log.Println("Email not present in header for the requested URL", req.URL.Path, email)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	restaurant_name := req.Header.Get(RestaurantName)
	var NO_RESTAURANTNAME string
	if restaurant_name == NO_RESTAURANTNAME {
		loggerUtil.Log.Println("RestaurantName not present in header for the requested URL", req.URL.Path, restaurant_name)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var c_bill billingappdb.Bill
	c_bill.Email = email
	c_bill.RestaurantName = restaurant_name

	restaurant_details, err := json.Marshal(c_bill)
	if err != nil {
		loggerUtil.Log.Println("Error: Converting Request json from struct to byte array", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	orders_list, err := http_current_server.billdb.Get(restaurant_details)
	if err != nil {
		loggerUtil.Log.Println("Error: Obtaining the orders list from DB: ", err.Error(),
			" for restaurant: ", string(restaurant_details))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(orders_list)
	return

}

// Open opens file
func (fs FileSystem) Open(path string) (http.File, error) {
	f, err := fs.fs.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if s.IsDir() {
		index := strings.TrimSuffix(path, "/") + "/index.html"
		if _, err := fs.fs.Open(index); err != nil {
			return nil, err
		}
	}

	return f, nil
}
func isValidEmail(email string) bool {
	return rxEmail.MatchString(email)
}
func validateEmail(w http.ResponseWriter, req *http.Request, c_bill_ptr *billingappdb.Bill) error {
	if req.Method == http.MethodGet {
		email := req.Header.Get(emailHeader)
		loggerUtil.Debugln("validateEmail: Email is " + email)
		var NO_EMAIL string
		if email == NO_EMAIL {
			loggerUtil.Log.Println("validateEmail: Email not present in header for the requested URL", req.URL.Path, email)
			return errors.New("Email field cannot be empty")
		}

		if !isValidEmail(email) {
			loggerUtil.Log.Println("validateEmail: Email is not valid: Get Request: " + email)
			return errors.New("Email is not valid " + email)
		}
		req.Header.Set(emailHeader, strings.ToLower(email))

	} else if req.Method == http.MethodPost {

		email := c_bill_ptr.Email
		var NO_EMAIL string
		if email == NO_EMAIL {
			loggerUtil.Log.Println("validateEmail: Email not present in header for the requested POST URL", req.URL.Path, email)
			return errors.New("Email field cannot be empty: POST request")
		}
		if !isValidEmail(email) {
			loggerUtil.Log.Println("validateEmail: Email is not valid: Post Reqest" + email)
			return errors.New("Email is not valid " + email)
		}
		loggerUtil.Log.Println("validateEmail: The value of email from Post Request is " + email)
		c_bill_ptr.Email = strings.ToLower(c_bill_ptr.Email)

	} else {
		loggerUtil.Log.Println("validateEmail: Error: Cannot have MEthod other than GET and Post")
		return errors.New("Only GET and POST request methods allowed")
	}
	return nil
}

func authorizeRequest(w http.ResponseWriter, req *http.Request, c_bill_ptr *(billingappdb.Bill), billDb *billingappdb.BillAppDB) error {

	token := req.Header.Get(authorizationHeader)
	var email string
	var NOTOKEN string
	if token == NOTOKEN {
		loggerUtil.Log.Println("authorizeRequest: Token not present in header for the requested URL", req.URL.Path, email)
		return errors.New("Token field cannot be empty")
	}
	if req.Method == http.MethodGet {
		email = req.Header.Get(emailHeader)
	} else if req.Method == http.MethodPost {

		email = c_bill_ptr.Email
		loggerUtil.Log.Println("authorizeRequest: The value of email from POST Request is " + email)

	} else {
		loggerUtil.Log.Println("authorizeRequest: Error: Cannot have MEthod other than GET and Post")
		return errors.New("Only GET and POST request methods allowed")
	}
	isValid, err := login.VerifyToken(email, token, billDb)
	if err != nil {
		loggerUtil.Log.Println("authorizeRequest: Failure Verify token " + token + " " + email)
		return errors.New("Failure: token verify of email: " + email)
	}
	if !isValid {
		loggerUtil.Debugln("Token not valid for current user: " + email)
		return errors.New("Token Not valid for current user: " + email)
	}
	loggerUtil.Debugln("Token valid for current user: " + email)
	return nil
}
func getCurrentBillEntries(w http.ResponseWriter, req *http.Request) (*(billingappdb.Bill), error) {
	var c_bill billingappdb.Bill
	if req.Method == http.MethodPost {
		err := decodeJSONBody(w, req, &c_bill)
		if err != nil {
			var mr *malformedRequest
			loggerUtil.Log.Println("Error: validateEmail: POST: Malformed Request: ", err.Error())
			if errors.As(err, &mr) {
				err = errors.New("Malformed Json in POST Request")
			} else {
				err = errors.New("Malformed Json in POST Request")
			}
			return &c_bill, err
		}
	}
	return &c_bill, nil

}
func getCertificateFiles() (string, string) {
	home_env := `HOME`
	home, ok := os.LookupEnv(home_env)
	if !ok {
		loggerUtil.Log.Println(home_env + ": NOT SET: Proceeding with /root as home")
		home = `/root`
	}
	certificateDir := home + `/certificate/`
	keypemFile := certificateDir + `key.pem`
	certpemFile := certificateDir + `cert.pem`
	file, err := os.Open(keypemFile)
	errStr := ""
	if err != nil {
		errStr += "Cannot open file: " + keypemFile + " "
	}
	file.Close()
	file, err = os.Open(certpemFile)
	if err != nil {
		errStr += "Cannot open file: " + certpemFile
	}
	file.Close()
	if errStr != "" {
		fmt.Println(errStr)
		loggerUtil.Log.Println(errStr)
		return "", ""
	}
	loggerUtil.Log.Println("Certificate Files: " + keypemFile + " " + certpemFile)
	return keypemFile, certpemFile

}

func httpHandleDumpRequest(req *http.Request) {

	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		loggerUtil.Log.Println("httpHandleDumpRequest: Dump Request Failed")
		return
	}
	loggerUtil.Log.Printf(string(dump))

}

func debugGetMethod(w http.ResponseWriter, req *http.Request) {
	email := req.Header.Get(emailHeader)
	loggerUtil.Log.Println("debugGetMethod: Debug request for " + email)
	if email != `saravana.k.r@gmail.com` {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong Email"))
	} else {
		loggerUtil.ToggleDebug()
		loggerUtil.Log.Println("debugGetMethod: Debug set to ", loggerUtil.GetDebug())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Debug Enabled: " + fmt.Sprintf("%v", loggerUtil.GetDebug())))
	}
}
