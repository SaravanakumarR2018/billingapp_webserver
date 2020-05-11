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
	"regexp"
	"strings"
	"cryptography"

	"github.com/golang/gddo/httputil/header"
)

const (
	Email string = "^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
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

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, emailToLower=true bool) error {
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
	if emailToLower == true {
		dst.Email = strings.ToLower(dst.Email)
	}
	return nil
}

type FileSystem struct {
	fs http.FileSystem
}
type httpServer struct {
	ip             string
	port           string
	fs_directory   string
	directory_url  string
	restaurant_url string
	billdb         *billingappdb.BillAppDB
}

var http_current_server httpServer

func Init(ip, port, fs_directory, directory_url, restaurant_url string, billdb *billingappdb.BillAppDB) {
	http_current_server = httpServer{
		ip:             ip,
		port:           port,
		fs_directory:   fs_directory,
		directory_url:  directory_url,
		restaurant_url: restaurant_url,
		billdb:         billdb,
	}
	new_port := flag.String("p", port, "port to serve on")
	directory := flag.String("d", fs_directory, "the directory of static file to host")
	flag.Parse()
	fileServer := http.FileServer(FileSystem{http.Dir(*directory)})
	http.Handle(directory_url, http.StripPrefix(strings.TrimRight(directory_url, directory_url), fileServer))
	http.HandleFunc(restaurant_url, umbrella_handler)
	fmt.Printf("Serving %s on HTTP port: %s\n", *directory, *new_port)
	loggerUtil.Log.Printf("Serving %s on HTTP port: %s\n", *directory, *new_port)
	log.Fatal(http.ListenAndServe(":"+*new_port, nil))
}
func umbrellaHandler(w http.ResponseWriter, req *http.Request) {
	loggerUtil.Debugln("Orders ", orders_url, restaurantlist_url, addnewrestaurant_url, loginHandler)
	orders_url := restaurant_url + `/orders`
	restaurantlist_url := restaurant_url + `/restaurantlist`
	addnewrestaurant_url := restaurant_url + `/addnewrestaurant`
	loginHandlerUrl := restaurant_url + `/login`
	resetPasswordUrl := restaurant_url + `/resetPassword`
	forgotPasswordUrl := restaurant_url + `/forgotPassword`
	add_CORS_headers(w, req)
	if req.Method == http.MethodOptions {
		loggerUtil.Debugln("umbrellaHandler: Processing OPTIONS method for CORS", req.URL.Path)
		processOptionsMethod(w, req)
		return
	}
	err := validateEmail(req)
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
	err := authorizeRequest(req)
	if err != nil {
		loggerUtil.Log.Println("umbrellaHandler: Error: Request Not Authorized: " + err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid Session and User"))
		return
	}

	if req.URL.Path == orders_url {
		orders_handler(w, req)
		return
	} else if req.URL.Path == restaurantlist_url {
		restaurantlist_handler(w, req)
		return
	} else if req.URL.Path == addnewrestaurant_url {
		addnewrestaurant_handler(w, req)
		return
	} else if req.URL.Path == resetPasswordUrl {
		resetPassword_handler(w, req)
		return
	} else if req.URL.Path == forgotPasswordUrl {
		forgotPassword_handler(w, req)
		return
	} else {
		loggerUtil.Log.Debugln("Bad request url ", req.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
	}
}
func resetPassword_handler (w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("resetPassword_handler: Processing GET method", req.URL.Path)
		login.ChangePassword(w, req, http_current_server.billdb)
	} else {
		loggerUtil.Debugln("resetPassword_handler: Bad Request ", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func forgotPassword_handler (w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("forgotPassword_handler: Processing GET method", req.URL.Path)
		login.ForgotPassword(w, req, http_current_server.billdb)
	} else {
		loggerUtil.Debugln("forgotPassword_handler: Bad Request ", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
} 
func loginHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("loginHandler: Processing GET method", req.URL.Path)
		login.ProcessLoginGetMethod(w, req)
	} else {
		loggerUtil.Debugln("loginHandler: Bad Request ", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}

}

func addnewrestaurant_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		loggerUtil.Debugln("addnewrestaurant_handler: Processing POST method", req.URL.Path)
		processAddNewRestaurantMethod(w, req)
	} else {
		loggerUtil.Debugln("addnewrestaurant_handler: Bad Request", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func processOptionsMethod(w http.ResponseWriter, req *http.Request) {
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

func orders_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		loggerUtil.Debugln("orders_handler: Processing POST method", req.URL.Path)
		processPOSTMethod(w, req)
	} else if req.Method == http.MethodGet {
		loggerUtil.Debugln("orders_handler: Processing GET method", req.URL.Path)
		processGETMethod(w, req)
	} else {
		loggerUtil.Debugln("orders_handler: Bad Request", req.URL.Path, req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}
func processAddNewRestaurantMethod(w http.ResponseWriter, req *http.Request) {
	content_type := req.Header.Get("Content-type")
	if !strings.Contains(content_type, `application/json`) {
		loggerUtil.Log.Println("Error: processAddNewRestaurantMethod: POST: The post operation should contain json data")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var c_bill billingappdb.Bill
	err := decodeJSONBody(w, req, &c_bill)
	if err != nil {
		var mr *malformedRequest
		loggerUtil.Log.Println("Error: processAddNewRestaurantMethod: POST: Malformed Request: ", err.Error())
		if errors.As(err, &mr) {
			http.Error(w, mr.msg, mr.status)
		} else {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}
	restaurant_id, err := http_current_server.billdb.Get_id_and_update_restaurant_db_tables(&c_bill)
	if err != nil {
		loggerUtil.Log.Println("Error: processAddNewRestaurantMethod: Cannot add new restaiurant", c_bill.Email,
			c_bill.RestaurantName)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	loggerUtil.Debugln("Restaurant id " + string(restaurant_id) + " " + c_bill.Email + " " + c_bill.RestaurantName)
	w.WriteHeader(http.StatusOK)
	return

}
func processPOSTMethod(w http.ResponseWriter, req *http.Request) {
	content_type := req.Header.Get("Content-type")
	if !strings.Contains(content_type, `application/json`) {
		loggerUtil.Log.Println("Error: POST: The post operation should contain json data")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var c_bill billingappdb.Bill
	err := decodeJSONBody(w, req, &c_bill)
	if err != nil {
		var mr *malformedRequest
		loggerUtil.Log.Println("Error: POST: Malformed Request: ", err.Error())
		if errors.As(err, &mr) {
			http.Error(w, mr.msg, mr.status)
		} else {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}
	current_bill, err := json.Marshal(c_bill)
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
	email := req.Header.Get("Email")
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

	email := req.Header.Get("Email")
	var NO_EMAIL string
	if email == NO_EMAIL {
		loggerUtil.Log.Println("Email not present in header for the requested URL", req.URL.Path, email)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	restaurant_name := req.Header.Get("RestaurantName")
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
	return rxEmail.MatchString(str)
}
func validateEmail(req *http.Request) error {
	emailHeader = "Email"
	if req.Method == http.MethodGet {
		email := req.Header.Get(emailHeader)
		var NO_EMAIL string
		if email == NO_EMAIL {
			loggerUtil.Log.Println("validateEmail: Email not present in header for the requested URL", req.URL.Path, email)
			return errors.New("Email field cannot be empty")
		}
		
		if !isValidEmail(email) {
			loggerUtil.Log.Println("validateEmail: Email is not valid: Get Request: " + email)
			return errors.New("Email is not valid " + email)
		}

	} else if req.Method == http.MethodPost {

		var c_bill billingappdb.Bill
		err := decodeJSONBody(w, req, &c_bill, emailToLower=false)
		if err != nil {
			var mr *malformedRequest
			loggerUtil.Log.Println("Error: validateEmail: POST: Malformed Request: ", err.Error())
			if errors.As(err, &mr) {
				err = errors.New("Malformed Json in POST Request")
			} else {
				err = errors.New("Malformed Json in POST Request")
			}
			return err
		}
		email := c_bill.Email
		var NO_EMAIL string
		if email == NO_EMAIL {
			loggerUtil.Log.Println("validateEmail: Email not present in header for the requested POST URL", req.URL.Path, email)
			return errors.New("Email field cannot be empty: POST request")
		}
		if !isValidEmail(email) {
			loggerUtil.Log.Println("validateEmail: Email is not valid: Post Reqest" + email)
			return errors.New("Email is not valid " + email)
		}


	} else {
		loggerUtil.Log.Println("validateEmail: Error: Cannot have MEthod other than GET and Post")
		return errors.New("Only GET and POST request methods allowed")
	}
	return nil
}

func authorizeRequest(req *http.Request) error {
	emailHeader = "Email"
	authorizationHeader = "Authorization"
	token := req.Header.Get(authorizationHeader)
	var email string
	var NOTOKEN string
	if token == NOTOKEN {
		loggerUtil.Log.Println("authorizeRequest: Token not present in header for the requested URL", req.URL.Path, email)
		return errors.New("Token field cannot be empty")
	}
	if req.Method == http.MethodGet {
		email := req.Header.Get(emailHeader)
	} else if req.Method == http.MethodPost {

		var c_bill billingappdb.Bill
		err := decodeJSONBody(w, req, &c_bill)
		email := c_bill.Email

	} else {
		loggerUtil.Log.Println("authorizeRequest: Error: Cannot have MEthod other than GET and Post")
		return errors.New("Only GET and POST request methods allowed")
	}
	tokenString,err := cryptography.Decrypt(token)
	if err != nil {
		loggerUtil.Log.Println("authorizeRequest: Error Decrypting Token " + token)
		return errors.New("Decrypting Token Failure")
	}
	if email != tokenString {
		loggerUtil.Debugln("Token not valid for current user: " + email)
		return errors.New("Token Not valid for current user: " + email)
	}
	loggerUtil.Debugln("Token valid for current user: " + email)
	return nil
}