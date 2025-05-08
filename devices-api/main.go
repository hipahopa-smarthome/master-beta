package main

import (
	"devices-api/db"
	"devices-api/handlers"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"os"
)

var (
	PORT        = os.Getenv("PORT")
	PostgresUrl = os.Getenv("POSTGRES_URL")
)

func main() {
	router := gin.Default()

	if PostgresUrl == "" {
		PostgresUrl = "host=localhost user=user password=insecure dbname=smart-home port=5432 sslmode=disable"
	}
	database := db.Connect(PostgresUrl)

	handlers.RegisterYandexRoutes(router, database)

	if PORT == "" {
		PORT = "8000"
	}
	log.Printf("Listening on port %s\n", PORT)
	log.Fatal(router.Run(fmt.Sprintf(":%s", PORT)))
}
