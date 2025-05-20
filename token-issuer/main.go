package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"os"
	"token-issuer/handlers"
)

var (
	PORT = os.Getenv("PORT")
)

// this service is for local (manufacturing, private) usage only
func main() {
	router := gin.Default()

	handlers.RegisterRoutes(router)

	if PORT == "" {
		PORT = "8080"
	}
	log.Printf("Listening on port %s\n", PORT)
	log.Fatal(router.Run(fmt.Sprintf(":%s", PORT)))
}
