package main

import (
	"ca-service/db"
	"ca-service/handlers"
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

	// init psql
	if PostgresUrl == "" {
		PostgresUrl = "host=localhost user=user password=insecure dbname=smart-home port=5432 sslmode=disable"
	}
	database := db.Connect(PostgresUrl)

	// init redis
	if RedisUrl == "" {
		RedisUrl = "localhost:6379"
	}
	redisClient := db.NewRedisClient(RedisUrl)

	err := handlers.RegisterCertsRoutes(router, database, redisClient)
	if err != nil {
		log.Printf("error initializing router: %v", err)
		return
	}

	if PORT == "" {
		PORT = "8080"
	}
	log.Printf("Listening on port %s\n", PORT)
	log.Fatal(router.Run(fmt.Sprintf(":%s", PORT)))
}
