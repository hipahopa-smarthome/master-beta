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
	PORT        = os.Getenv("PORT")
	PostgresUrl = os.Getenv("POSTGRES_URL")
	RedisUrl    = os.Getenv("REDIS_URL")
)

func main() {
	router := gin.Default()

	if PostgresUrl == "" {
		PostgresUrl = "host=localhost user=user password=insecure dbname=smart-home port=5432 sslmode=disable"
	}
	database := db.Connect(PostgresUrl)

	if RedisUrl == "" {
		RedisUrl = "localhost:6379"
	}
	rdb := db.NewRedisClient(RedisUrl)

	handlers.RegisterAuthRoutes(router, database, rdb)

	if PORT == "" {
		PORT = "8000"
	}
	log.Printf("Listening on port %s\n", PORT)
	log.Fatal(router.Run(fmt.Sprintf(":%s", PORT)))
}
