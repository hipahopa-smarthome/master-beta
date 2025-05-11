package db

import (
	"context"
	"github.com/go-redis/redis/v8"
	"log"
)

type RedisClients struct {
	DB0 *redis.Client
	DB1 *redis.Client
}

func NewRedisClients(addr string) *RedisClients {
	db0 := newRedisClient(addr, 0)
	db1 := newRedisClient(addr, 1)

	return &RedisClients{
		DB0: db0,
		DB1: db1,
	}
}

func newRedisClient(addr string, db int) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   db,
	})

	if _, err := client.Ping(context.Background()).Result(); err != nil {
		log.Fatalf("Failed to connect to Redis DB %d: %v", db, err)
	}

	return client
}
