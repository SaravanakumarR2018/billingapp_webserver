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
	"net/http"
	"strings"

	"github.com/golang/gddo/httputil/header"
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
		if value != "application/json" {
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
	orders_url := restaurant_url + `/orders`
	http.HandleFunc(orders_url, orders_handler)
	restaurantlist_url := restaurant_url + `/restaurantlist`
	http.HandleFunc(restaurantlist_url, restaurantlist_handler)
	loggerUtil.Debugln("Orders url and restaurant list url ", orders_url, restaurantlist_url)

	fmt.Printf("Serving %s on HTTP port: %s\n", *directory, *new_port)
	loggerUtil.Log.Printf("Serving %s on HTTP port: %s\n", *directory, *new_port)
	log.Fatal(http.ListenAndServe(":"+*new_port, nil))
}

func restaurantlist_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		loggerUtil.Debugln("Processing GET method", req.URL.Path)
		processRstrntListGETMethod(w, req)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func orders_handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		loggerUtil.Debugln("Processing POST method", req.URL.Path)
		processPOSTMethod(w, req)
	} else if req.Method == http.MethodGet {
		loggerUtil.Debugln("Processing GET method", req.URL.Path)
		processGETMethod(w, req)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func processPOSTMethod(w http.ResponseWriter, req *http.Request) {
	content_type := req.Header.Get("Content-type")
	if content_type != `application/json` {
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
