package db

import (
	"context"
	"github.com/go-redis/redis/v8"
	"log"
)

func NewRedisClient(addr string) (*redis.Client, *redis.Client) {
	client0 := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   0,
	})

	client1 := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   1,
	})

	_, err := client0.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis db 0: %v", err)
	}

	_, err = client1.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis db 1: %v", err)
	}

	return client0, client1
}
