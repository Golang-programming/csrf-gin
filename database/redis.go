package database

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"
)

var RedisDB *redis.Client
var ctx = context.Background()

func InitializeRedis() {
	RedisDB = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
}

func Set(key string, value interface{}) {
	if err := RedisDB.Set(ctx, key, value, 0).Err(); err != nil {
		log.Fatal("Failed to set key:", err)
	}
}

func Get(key string) string {
	val, err := RedisDB.Get(ctx, key).Result()
	if err == redis.Nil {
		log.Fatal("Key not found:", key)
	} else if err != nil {
		log.Fatal("Failed to get key:", err)
	}

	return val
}

func Delete(key string) {
	if err := RedisDB.Del(ctx, key).Err(); err != nil {
		log.Fatal("Failed to delete key:", err)
	}
}

func Has(key string) bool {
	count, err := RedisDB.Exists(ctx, key).Result()
	if err != nil {
		log.Fatal("Failed to check if key exists:", err)
	}

	return count > 0
}
