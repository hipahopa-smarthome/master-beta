package main

import (
	"auth-server/db"
	"auth-server/handlers"
	"auth-server/service"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"log"
	"os"
	"time"
)

var (
	Port        = os.Getenv("PORT")
	PostgresUrl = os.Getenv("POSTGRES_URL")
	RedisUrl    = os.Getenv("REDIS_URL")
)

func main() {
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"*"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// init psql
	if PostgresUrl == "" {
		PostgresUrl = "host=localhost user=user password=insecure dbname=smart-home port=5432 sslmode=disable"
	}
	database := db.Connect(PostgresUrl)

	// init redis
	if RedisUrl == "" {
		RedisUrl = "localhost:6379"
	}
	redisClients := db.NewRedisClients(RedisUrl)

	defer func(DB0 *redis.Client) {
		err := DB0.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(redisClients.DB0)
	defer func(DB1 *redis.Client) {
		err := DB1.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(redisClients.DB1)

	// init smtp
	smtpConfig := service.SmtpConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     os.Getenv("SMTP_PORT"),
		Password: os.Getenv("SMTP_PASSWORD"),
		Username: os.Getenv("SMTP_USERNAME"),
	}

	// register routes
	handlers.RegisterAuthRoutes(router, database, redisClients, smtpConfig)

	if Port == "" {
		Port = "8080"
	}
	log.Printf("Listening on port %s\n", Port)
	log.Fatal(router.Run(fmt.Sprintf(":%s", Port)))
}
