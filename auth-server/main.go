package main

import (
	"auth-server/db"
	"auth-server/handlers"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"os"
)

var (
	PORT = os.Getenv("PORT")
)

func main() {
	router := gin.Default()

	dsn := "host=localhost user=user password=insecure dbname=smart-home port=5432 sslmode=disable"
	database := db.Connect(dsn)

	rdb := db.NewRedisClient("localhost:6379")

	handlers.RegisterAuthRoutes(router, database, rdb)

	if PORT == "" {
		PORT = "8000"
	}
	log.Printf("Listening on port %s\n", PORT)
	log.Fatal(router.Run(fmt.Sprintf(":%s", PORT)))
}
