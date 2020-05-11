package billingappdb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"loggerUtil"
	"strconv"
	"time"

	// for mysql
	_ "github.com/go-sql-driver/mysql"
)

type restaurant_db_tables struct {
	dishes          string
	orders          string
	order_updations string
	customer_table  string
}
type BillAppDB struct {
	Billdb              *sql.DB
	Host                string
	Port                string
	Username            string
	Password            string
	DBname              string
	RestaurantTableName string
	PasswordTableName   string
}
type DishEntry struct {
	Index      uint
	DishName   string
	Price      float32
	Tax        float32
	TaxPercent float32
	Quantity   uint
}
type Bill struct {
	Email          string
	RestaurantName string
	UUID           string
	CustomerName   string
	TableName      string
	DishRows       []DishEntry
}

func (b *Bill) Validate() error {
	set := make(map[string]bool)
	for _, d := range b.DishRows {
		_, exists := set[d.DishName]
		if exists == true {
			return errors.New("Bill cannot have repeated Dish: " + d.DishName)
		}
		set[d.DishName] = true
	}
	return nil
}

func Init(Host, Port, Username, Password, DBname string) (BillAppDB, error) {
	//fmt.Println("begin init")
	loggerUtil.Debugln("Billing app DB Init: begin")
	dsn := Username + ":" + Password + "@tcp(" + Host + ":" + Port + ")/" + DBname
	Billdb, err := sql.Open("mysql", dsn)
	if err != nil {
		loggerUtil.Log.Println("Error Opening DB: " + Host + Port + Username + Password + DBname + err.Error())
		bappdb := BillAppDB{}
		loggerUtil.Debugln("Billing app DB Init Abort: end")
		return bappdb, err
	}
	db_ping := false
	for i := 0; i < 1800; i++ {
		err = Billdb.Ping()
		if err != nil {
			loggerUtil.Log.Println("Error: DB not pingable: " + Host + Port + Username + Password + DBname + err.Error())
			loggerUtil.Debugln("Billing app DB Init Ping Abort: end")
		} else {
			db_ping = true
			loggerUtil.Log.Println("SUCCESS: DB Ping : sleep interval: 100ms: trial count: ", i)
			break
		}
		time.Sleep(100 * time.Millisecond)
		loggerUtil.Log.Println("Error: DB Ping missed: checking after 100 ms: trial: ", i)
	}
	if db_ping == false {
		loggerUtil.Log.Println("Error: Could not connect to DB for 10 seconds: Exit")
		return BillAppDB{}, err
	}
	bappdb := BillAppDB{Billdb, Host, Port, Username, Password, DBname, "restaurant", "password"}

	loggerUtil.Debugln(bappdb.Host + bappdb.Port + bappdb.Username + bappdb.Password +
		bappdb.DBname + bappdb.RestaurantTableName + bappdb.PasswordTableName)

	exec_str := `CREATE TABLE IF NOT EXISTS ` + bappdb.RestaurantTableName + ` (
		id INT NOT NULL AUTO_INCREMENT,
		email VARCHAR(1024) NOT NULL,
		name VARCHAR(255) NOT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id)
	);`
	_, err = Billdb.Exec(exec_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Exec create table restaurant failed" + err.Error())
		return bappdb, err
	}

	exec_str = `CREATE TABLE IF NOT EXISTS ` + bappdb.PasswordTableName + ` (
		email VARCHAR(1024) NOT NULL,
		passwordmd5 BINARY(16) NOT NULL,
		create_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_update_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`
	_, err = Billdb.Exec(exec_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Exec create table password failed" + err.Error())
		return bappdb, err
	}
	return bappdb, nil

}
func (b *BillAppDB) Close() error {
	err := b.Billdb.Close()
	if err != nil {
		loggerUtil.Log.Println("Error: While closing the DB connection ", err.Error())
		return err
	}
	loggerUtil.Log.Println("SUCCESS: DB: CLOSED: ", b.Host)
	return nil
}
func (b *BillAppDB) GetRestaurantList(email []byte) ([]byte, error) {
	var restaurant_list []byte
	var email_details Bill
	err := json.Unmarshal(email, &email_details)
	if err != nil {
		loggerUtil.Log.Println("Error: UnMarshallig restaurant details", err.Error())
		return restaurant_list, err
	}
	query_str := `SELECT name FROM restaurant WHERE email="` + email_details.Email + `"`
	restaurant_list_map, err := b.getQueryJson(query_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Obtaining restaurant list from email", err.Error())
		return restaurant_list, err
	}
	restaurant_list, err = json.Marshal(restaurant_list_map)
	if err != nil {
		loggerUtil.Log.Println("Error: Converting restaurant list from map to byte array", err.Error())
		return restaurant_list, err
	}
	return restaurant_list, err
}
func (b *BillAppDB) Get(restrnt []byte) ([]byte, error) {
	var return_value []byte
	var restaurant_details Bill
	err := json.Unmarshal(restrnt, &restaurant_details)
	if err != nil {
		loggerUtil.Log.Println("Error: UnMarshallig restaurant details", err.Error())
		return return_value, err
	}
	restaurant_id, err := b.get_restaurant_id(&restaurant_details)
	if err != nil {
		loggerUtil.Log.Println("Get: Get restaurant id Failed: ", err.Error())
		return return_value, err
	}
	if restaurant_id == 0 {
		loggerUtil.Log.Println("Error: Wrong Email or Restaurant Name")
		return return_value, nil
	}
	rstrnt_db_tables := get_restaurant_table_names(restaurant_id)
	query_str := `SELECT order_id,  dishes_id, Quantity, dish_index, dish_name, price,tax_percent, tax,
	BIN_TO_UUID(CUST_TABLE.uuid) as uuid, customer_id, customer_name, table_name, timestamp FROM 
	(SELECT * FROM ` + rstrnt_db_tables.orders + ` 
	JOIN (SELECT OD.uuid as uuid, timestamp, order_id as max_order_id FROM (SELECT DISTINCT uuid, timestamp, order_id from ` + rstrnt_db_tables.order_updations + `) OD
	INNER JOIN (SELECT uuid, MAX(order_id) as max_order_id FROM ` + rstrnt_db_tables.order_updations + ` GROUP BY uuid) calq
	on calq.max_order_id = OD.order_id ) t
	ON t.max_order_id = order_id) AS ORDER_TABLE 
	JOIN (SELECT * FROM ` + rstrnt_db_tables.customer_table + `) as CUST_TABLE
	WHERE ORDER_TABLE.uuid = CUST_TABLE.uuid`

	json_map, err := b.getQueryJson(query_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Querying the database for restaurant orders ", query_str, err.Error())
		return return_value, err
	}
	return_value, err = json.Marshal(json_map)
	if err != nil {
		loggerUtil.Log.Println("Error: Marshalling json map for orders to byte array: ", err.Error())
		return return_value, err
	}
	return return_value, nil
}
func (b *BillAppDB) Insert(current_bill []byte) error {

	var c_bill Bill
	err := json.Unmarshal(current_bill, &c_bill)
	if err != nil {
		loggerUtil.Log.Println("Error Unmarshalling current bill", err)
		return err
	}
	err = c_bill.Validate()
	if err != nil {
		loggerUtil.Log.Println("DB insert: Validate Failed")
		return err
	}
	restaurant_id, err := b.Get_id_and_update_restaurant_db_tables(&c_bill)
	if err != nil {
		loggerUtil.Log.Println("Error: Getting table id", err.Error())
		return err
	}
	loggerUtil.Debugln("Restaurant id", restaurant_id)
	current_timestamp, err := b.get_current_timestamp()
	if err != nil {
		loggerUtil.Log.Println("Error: Get timestamp failed")
		return err
	}
	order_id, err := b.insert_curent_order_updations(&c_bill, current_timestamp, restaurant_id)
	if err != nil {
		loggerUtil.Log.Println("Error: Failed to obtain the order_id", err.Error())
		return err
	}
	err = b.insert_dishes(c_bill, current_timestamp, restaurant_id, order_id)
	if err != nil {
		loggerUtil.Log.Println("Error: updating dishes ", err.Error())
		return err
	}

	return nil
}
func (b *BillAppDB) insert_curent_order_updations(c_bill *Bill, current_timestamp string, restaurant_id uint) (uint64, error) {
	rt_db_tbls := get_restaurant_table_names(restaurant_id)

	query_customer_exists_str := `SELECT * FROM ` + rt_db_tbls.customer_table + ` WHERE BIN_TO_UUID(uuid)="` + c_bill.UUID + `"`
	json_arr, err := b.getQueryJson(query_customer_exists_str)
	if err != nil {
		loggerUtil.Log.Println("Error: quering from customer table ", query_customer_exists_str, err.Error())
		return 0, err
	}
	if len(json_arr) == 0 {
		loggerUtil.Log.Println("New Order with UUID " + c_bill.UUID)
		//Insert a new element into customer table
		insert_str := `INSERT INTO ` + rt_db_tbls.customer_table + ` (uuid, customer_name, table_name) 
		VALUES(` + `UUID_TO_BIN("` + c_bill.UUID + `"), "` + c_bill.CustomerName + `", "` + c_bill.TableName + `")`
		err := b.Exec(insert_str)
		if err != nil {
			loggerUtil.Log.Println("Error: inserting into Customer table ", insert_str, err.Error())
			return 0, err
		}
	}
	if len(json_arr) == 1 {
		//Customer entry already exists look for updations
		FIRST_ELEMENT := 0
		saved_cust_name := json_arr[FIRST_ELEMENT]["customer_name"]
		saved_table_name := json_arr[FIRST_ELEMENT]["table_name"]
		cust_id := json_arr[FIRST_ELEMENT]["customer_id"]
		if saved_cust_name != c_bill.CustomerName || saved_table_name != c_bill.TableName {
			//We got to re-update the table with the entry
			update_str := `UPDATE ` + rt_db_tbls.customer_table + ` SET customer_name= "` +
				c_bill.CustomerName + `", table_name= "` + c_bill.TableName + `" WHERE customer_id=` + cust_id
			err := b.Exec(update_str)
			if err != nil {
				loggerUtil.Log.Println("Error: Updating Customer table ", update_str, err.Error())
				return 0, err
			}
			loggerUtil.Debugln(`SUCCESS: Updating Customer Table: ` + c_bill.CustomerName + ` ` + c_bill.TableName)
		}
	}
	insert_str := `INSERT INTO ` + rt_db_tbls.order_updations + ` (uuid, timestamp)` +
		`VALUES (` +
		`UNHEX(REPLACE("` + c_bill.UUID + `", "-", "")), "` + current_timestamp + `")`
	err = b.Exec(insert_str)
	if err != nil {
		loggerUtil.Log.Println("Error: inserting into Order Updations table ", insert_str, err.Error())
		return 0, err
	}

	query_str := `SELECT order_id FROM ` + rt_db_tbls.order_updations + ` WHERE ` +
		` uuid= UNHEX(REPLACE("` + c_bill.UUID + `", "-", "")) AND timestamp= "` + current_timestamp + `"`
	json_arr, err = b.getQueryJson(query_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Failed to obtain the updated order_id ", query_str, err.Error())
		return 0, err
	}
	FIRST_ELEMENT := 0
	order_id, err := strconv.ParseUint(json_arr[FIRST_ELEMENT]["order_id"], 10, 64)
	if err != nil {
		loggerUtil.Log.Println("Error:  while parsing uint64", json_arr[FIRST_ELEMENT]["order_id"])
		return 0, err
	}
	loggerUtil.Log.Println("Success: Order id is", order_id)
	return order_id, nil

}
func (b *BillAppDB) insert_dish_and_get_id(d DishEntry, current_timestamp string, rt_db_tables restaurant_db_tables) (uint64, error) {
	insert_str := `INSERT INTO ` + rt_db_tables.dishes + ` (name, timestamp, price, tax_percent, tax) ` + ` VALUES ("` + d.DishName + `", "` + current_timestamp + `", ` +
		fmt.Sprintf("%f", d.Price) + `, ` + fmt.Sprintf("%f", d.TaxPercent) + `, ` + fmt.Sprintf("%f", d.Tax) + `)`
	err := b.Exec(insert_str)
	if err != nil {
		loggerUtil.Log.Println("Error: while inserting dish into dish table", d, err.Error())
		return 0, err
	}
	query_str := `SELECT id FROM ` + rt_db_tables.dishes + ` WHERE ` +
		`name = "` + d.DishName + `" AND ` +
		`timestamp = "` + current_timestamp + `"`

	json_arr, err := b.getQueryJson(query_str)
	if err != nil {
		loggerUtil.Log.Println("Error: while retriving dish ID back ", err.Error())
		return 0, err
	}

	FIRST_ELEMENT := 0
	dishes_id, err := strconv.ParseUint(json_arr[FIRST_ELEMENT]["id"], 10, 64)
	if err != nil {
		loggerUtil.Log.Println("Error: while converting dishes id to int", err.Error())
		return 0, err
	}
	loggerUtil.Debugln("Dishes ID", dishes_id, d)
	return dishes_id, err

}
func (b *BillAppDB) insert_orders(d *DishEntry, dishes_id, order_id uint64, rt_db_tbls restaurant_db_tables) error {
	insert_str := `INSERT INTO ` + rt_db_tbls.orders + ` (dish_index, order_id, dishes_id, Quantity, dish_name, price, tax_percent, tax) ` +
		` VALUES (` + fmt.Sprintf("%v", d.Index) + `, ` + fmt.Sprintf("%v", order_id) + `, ` + fmt.Sprintf("%v", dishes_id) + `,` + fmt.Sprintf("%v", d.Quantity) + `, "` + d.DishName + `", ` + fmt.Sprintf("%f", d.Price) + `, ` +
		fmt.Sprintf("%f", d.TaxPercent) +
		`, ` + fmt.Sprintf("%f", d.Tax) + `)`
	err := b.Exec(insert_str)
	if err != nil {
		loggerUtil.Log.Println("Error: while inserting orders into orders table", d, err.Error())
		return err
	}
	return nil

}
func (b *BillAppDB) insert_dishes(c_bill Bill, current_timestamp string, restaurant_id uint, order_id uint64) error {
	rt_db_tbls := get_restaurant_table_names(restaurant_id)
	for _, d := range c_bill.DishRows {
		dishes_id, err := b.insert_dish_and_get_id(d, current_timestamp, rt_db_tbls)
		if err != nil {
			loggerUtil.Log.Println("Error: inserting dishes into dishes table", err.Error())
			return err
		}
		err = b.insert_orders(&d, dishes_id, order_id, rt_db_tbls)
		if err != nil {
			loggerUtil.Log.Println("Error: while insering orders into orders table", err.Error())
			return err
		}

	}
	return nil
}
func (b *BillAppDB) get_restaurant_id(restrnt_details *Bill) (uint, error) {
	var restaurant_id uint
	query_str := `SELECT id from ` + b.RestaurantTableName + ` WHERE email="` + restrnt_details.Email +
		`" AND name="` + restrnt_details.RestaurantName + `"`
	loggerUtil.Debugln("get_restaurant_id: Restaurant id query string is" + query_str)
	restaurant_str, err := b.getQueryJson(query_str)
	if err != nil {
		loggerUtil.Log.Println("get_restaurant_id: Get json query failed: " + query_str + err.Error())
		return 0, err
	}
	if len(restaurant_str) == 0 {
		loggerUtil.Log.Println("get_restaurant_id: No Table Present: Returning restaurant if as 0")
		return 0, nil
	}
	FIRST_ELEMENT := 0
	r := restaurant_str[FIRST_ELEMENT]
	loggerUtil.Debugln("get_restaurant_id: Restaurant: ", restaurant_str)
	loggerUtil.Debugln("get_restaurant_id: First Restaurant map ", r, r["id"])
	r_id, err := strconv.ParseUint(r["id"], 10, 32)
	if err != nil {
		loggerUtil.Log.Println("get_restaurant_id: Error: converting restaurant id to uint failed: ", err.Error())
		return restaurant_id, err
	}
	restaurant_id = uint(r_id)
	return restaurant_id, nil
}
func (b *BillAppDB) Get_id_and_update_restaurant_db_tables(c_bill *Bill) (uint, error) {
	var restaurant_id uint
	query_str := `SELECT id from ` + b.RestaurantTableName + ` WHERE email="` + c_bill.Email +
		`" AND name="` + c_bill.RestaurantName + `"`
	loggerUtil.Debugln("query string is" + query_str)
	restaurant_str, err := b.getQueryJson(query_str)
	//loggerUtil.Log.Println("Restaurant str is" + string(restaurant_str))
	if err != nil {
		loggerUtil.Log.Println("Get json query failed: " + query_str + err.Error())
		return restaurant_id, err
	}
	new_table_created := false
	if len(restaurant_str) == 0 {
		insert_values := b.get_restaurant_insert_string(c_bill.Email, c_bill.RestaurantName)
		_, err := b.Billdb.Exec(insert_values)
		if err != nil {
			loggerUtil.Log.Println("Insert  restaurant table Email and Restaurant Name failed: " + err.Error())
			return restaurant_id, err
		}
		query_str := `SELECT id from ` + b.RestaurantTableName + ` WHERE email="` + c_bill.Email +
			`" AND name="` + c_bill.RestaurantName + `"`
		restaurant_str, err = b.getQueryJson(query_str)
		//loggerUtil.Log.Println("Restaurant str Second time is" + restaurant_str)
		if err != nil {
			loggerUtil.Log.Println("Get json query failed: " + query_str + err.Error())
			return restaurant_id, err
		}
		new_table_created = true
	}
	r := restaurant_str[0]
	loggerUtil.Debugln("Restaurant: ", restaurant_str)
	loggerUtil.Debugln("First Restaurant map ", r, r["id"])
	r_id, err := strconv.ParseUint(r["id"], 10, 32)
	if err != nil {
		loggerUtil.Log.Println("Error: converting restaurant id to uint failed: ", err.Error())
		return restaurant_id, err
	}
	restaurant_id = uint(r_id)
	loggerUtil.Debugln("table id ", restaurant_id)
	if err != nil {
		loggerUtil.Log.Println("Error: Converting Table id failed: " + r["id"])
		return restaurant_id, err
	}
	loggerUtil.Log.Println("Table Id obtained is", restaurant_id)
	// If we have created a new Restaurant
	// We have to create the corresponding tables
	if new_table_created == true {
		err := b.create_restaurant_db_tables(restaurant_id)
		if err != nil {
			loggerUtil.Log.Println("Error: Creating DB TABLES for restaurant ID Failed: Restaurant id", restaurant_id)
			return restaurant_id, err
		}
	}
	return restaurant_id, nil
}

func (b *BillAppDB) get_restaurant_insert_string(email, restaurantName string) string {
	return_str := `INSERT INTO ` + b.RestaurantTableName + ` (email, name) VALUES ("` +
		email + `", "` + restaurantName + `")`
	loggerUtil.Debugln("get_restaurant_json: String " + return_str)
	return (return_str)

}

func (b *BillAppDB) getQueryJson(sqlString string) ([]map[string]string, error) {
	var return_map []map[string]string
	loggerUtil.Debugln("getQueryJson: sqlString: ", sqlString)
	rows, err := b.Billdb.Query(sqlString)
	if err != nil {
		loggerUtil.Log.Println("getQueryJson: Error: Querying the value for sqlString", sqlString, err.Error())
		return return_map, err
	}

	columns, err := rows.Columns()
	if err != nil {
		loggerUtil.Log.Println("getQueryJson: Error: Converting Rows into Columns", err.Error())
		return return_map, err
	}
	count := len(columns)
	tableData := make([]map[string]interface{}, 0)
	values := make([]interface{}, count)
	valuePtrs := make([]interface{}, count)
	for rows.Next() {
		for i := 0; i < count; i++ {
			valuePtrs[i] = &values[i]
		}
		rows.Scan(valuePtrs...)
		entry := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}
			entry[col] = v
		}
		tableData = append(tableData, entry)
	}
	jsonData, err := json.Marshal(tableData)
	if err != nil {
		loggerUtil.Log.Println("getQueryJson: Error: Converting tabledate  into json", err.Error())
		return return_map, err
	}
	loggerUtil.Debugln("Success: Json Rows output", string(jsonData))
	err = json.Unmarshal(jsonData, &return_map)
	if err != nil {
		loggerUtil.Log.Println("Converting json byte array to map failed", err.Error())
		return return_map, err
	}
	return return_map, nil
}

func (b *BillAppDB) create_restaurant_db_tables(restaurant_id uint) error {
	db_tb_names := get_restaurant_table_names(restaurant_id)
	order_updations_table_str := `CREATE TABLE IF NOT EXISTS ` + db_tb_names.order_updations + `(
		uuid BINARY(16) NOT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		order_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		PRIMARY KEY (order_id) 
	);`
	dishes_insert_table_str := `CREATE TABLE IF NOT EXISTS ` + db_tb_names.dishes + ` (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		name VARCHAR(255) NOT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		price FLOAT NOT NULL,
		tax_percent FLOAT ,
		tax FLOAT,
		PRIMARY KEY (id)
	)`
	orders_insert_table_str := `CREATE TABLE IF NOT EXISTS ` + db_tb_names.orders + ` (
		dish_index INT UNSIGNED NOT NULL,
		order_id BIGINT UNSIGNED NOT NULL,
		dishes_id BIGINT UNSIGNED NOT NULL,
		Quantity INT UNSIGNED NOT NULL,
		dish_name VARCHAR(255) NOT NULL,
		price FLOAT NOT NULL,
		tax_percent FLOAT,
		tax FLOAT,
		FOREIGN KEY(order_id) REFERENCES ` + db_tb_names.order_updations + `(order_id), 
		FOREIGN KEY (dishes_id) REFERENCES ` + db_tb_names.dishes + `(id)
	)`
	customer_table := `CREATE TABLE IF NOT EXISTS  ` + db_tb_names.customer_table + ` (
		uuid BINARY(16) NOT NULL,
		customer_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		customer_name VARCHAR(255),
		table_name VARCHAR(255),
		PRIMARY KEY(customer_id)
		)`

	err := b.Exec(order_updations_table_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Insert order updations table failed for restaurant id ", restaurant_id, err.Error())
		return err
	}
	loggerUtil.Debugln("ORDER UPDATIONS DB Table inserted: SUCCESS: Restaurant id: ", restaurant_id)
	err = b.Exec(dishes_insert_table_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Insert dishes table failed for restaurant id ", restaurant_id, err.Error())
		return err
	}
	loggerUtil.Debugln("Dishes DB Table inserted: SUCCESS: Restaurant id: ", restaurant_id)
	err = b.Exec(orders_insert_table_str)
	if err != nil {
		loggerUtil.Log.Println("Error: Insert orders table failed for restaurant id ", restaurant_id, err.Error())
		return err
	}
	loggerUtil.Debugln("ORDERS DB Table inserted: SUCCESS: Restaurant id: ", restaurant_id)
	err = b.Exec(customer_table)
	if err != nil {
		loggerUtil.Log.Println("Error: Insert customer table failed for restaurant id ", restaurant_id, err.Error())
		return err
	}
	loggerUtil.Debugln("CUSTOMER DB Table inserted: SUCCESS: Restaurant id: ", restaurant_id)

	loggerUtil.Debugln("All DB TABLES are successfully added for Restaurant id ", restaurant_id)
	return nil

}

func (b *BillAppDB) Exec(str string) error {
	_, err := b.Billdb.Exec(str)
	if err != nil {
		loggerUtil.Log.Println("Error: Exec: ", str, err.Error())
		return err
	}
	loggerUtil.Debugln("Exec: Success: ", str)
	return err
}

func get_restaurant_table_names(restaurant_id uint) restaurant_db_tables {
	loggerUtil.Debugln("Value of restaurant id value is", restaurant_id)
	begin_value := "_" + fmt.Sprintf("%v", restaurant_id) + "_"
	loggerUtil.Debugln("Value of begin value is", begin_value)
	returnValue := restaurant_db_tables{
		dishes:          begin_value + "dishes",
		orders:          begin_value + "orders",
		order_updations: begin_value + "order_updations",
		customer_table:  begin_value + "customer_table",
	}
	return returnValue
}

func (b *BillAppDB) get_current_timestamp() (string, error) {
	returnJson, err := b.getQueryJson("SELECT CURRENT_TIMESTAMP")
	if err != nil {
		loggerUtil.Log.Println("Error: Obtaining current timestamp from DB")
		return "", err
	}
	loggerUtil.Debugln("Obtained current timestamp", returnJson)
	FIRST_ELEMENT := 0
	return returnJson[FIRST_ELEMENT]["CURRENT_TIMESTAMP"], nil

}

func (b *BillAppDB) ResetPassword(email, password string) error {
	query_str := `SELECT email FROM ` + b.PasswordTableName + ` WHERE email="` + email + `"`
	userEntryMap, err := b.getQueryJson(query_str)
	if err != nil {
		loggerUtil.Log.Println("resetPassword: Error Obtaining userentry from password Table: ", query_str, err.Error())
		return err
	}
	if len(userEntryMap) == 0 {
		// First time - Add entry to the table
		execStr := `INSERT INTO ` + b.PasswordTableName +
			` (email, passwordmd5) VALUES ("` + email + `", UNHEX(MD5("` + password + `")))`
		err = b.Exec(execStr)
		if err != nil {
			execStr := `INSERT INTO ` + b.PasswordTableName +
				` (email, passwordmd5) VALUES ("` + email + `", UNHEX(MD5("` + "masked" + `")))`
			loggerUtil.Log.Println("resetPassword: Error: inserting into password table ", execStr, err.Error())
			return err
		}

	} else {
		timestamp, err := b.get_current_timestamp()
		if err != nil {
			loggerUtil.Log.Println("resetPassword: Error getting current timestamp: " + err.Error())
			return err
		}
		// update the entry with the new password
		execStr := `UPDATE ` + b.PasswordTableName + ` SET 
		passwordmd5=UNHEX(MD5("` + password + `")), 
		last_update_timestamp = "` + timestamp + `" WHERE 
		email = "` + email + `"`
		err = b.Exec(execStr)
		if err != nil {
			execStr := `UPDATE ` + b.PasswordTableName + ` SET 
			passwordmd5=UNHEX(MD5("` + "masked" + `")), 
			last_update_timestamp = "` + timestamp + `" WHERE 
			email = "` + email + `"`
			loggerUtil.Log.Println("resetPassword: Error: updating password table ", execStr, err.Error())
			return err
		}

	}
	return nil
}

func (b *BillAppDB) VerifyEmailAndPassword(email, password string) (bool, error) {
	query_str := `SELECT email FROM ` + b.PasswordTableName + ` WHERE email="` + email +
		`" AND password=UNHEX(MD5("` + password + `"))`
	maskedQueryStr := `SELECT email FROM ` + b.PasswordTableName + ` WHERE email="` + email +
		`" AND password=UNHEX(MD5("` + "masked" + `"))`
	userEntryMap, err := b.getQueryJson(query_str)
	if err != nil {

		loggerUtil.Log.Println("verifyEmailAndPassword: Error Obtaining userentry from password Table: ",
			maskedQueryStr, err.Error())
		return false, err
	}
	if len(userEntryMap) == 0 {
		loggerUtil.Log.Println("verifyEmailAndPassword: No Entry for given username and password", maskedQueryStr)
		return false, nil
	}
	loggerUtil.Debugln("verifyEmailAndPassword: PRESENT: Entry for given username and password", maskedQueryStr)
	return true, nil

}
