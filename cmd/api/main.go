package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"vue-api/internal/data"
	"vue-api/internal/driver"
)

// config is the type for all application configuration
type config struct {
	port int //what port do we want to listen on
}

// application is the type for all data we want to share with the
// various parts of our application. We will share this information in most
// cases by using this type of receiver for functions
type application struct {
	config   config
	infoLog  *log.Logger
	errorLog *log.Logger
	//importing custom Models package inside of ../../internal/data/models.go
	models data.Models
}

// main is the main point of entry for our application
func main() {
	var cfg config
	cfg.port = 8081

	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stdout, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	//specifying dsn at runtime
	// host=localhost port=5432 user=postgres password=password sslmode=disabled dbname=vueapi timezone=UTC connect_timeout=5
	dsn := os.Getenv("DSN")
	db, err := driver.ConnectPosgres(dsn)
	if err != nil {
		log.Fatal("Cannot connect to database")
	}
	defer db.SQL.Close()

	app := &application{
		config:   cfg,
		infoLog:  infoLog,
		errorLog: errorLog,
		//Using fucntion inside of data folder
		models: data.New(db.SQL),
	}
	err = app.serve()
	if err != nil {
		log.Fatal(err)
	}
}

// reciever of pointer to application
// server
func (app *application) serve() error {
	app.infoLog.Println("API listening on port", app.config.port)
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", app.config.port),
		Handler: app.routes(),
	}

	return srv.ListenAndServe()
}
