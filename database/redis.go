package database

import (
	"context"
	"errors"

	"github.com/redis/go-redis/v9"
)

var RedisDB *redis.Client
var ctx = context.Background()

func InitializeRedis() {
	RedisDB = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
}

func Set(key string, value interface{}) error {
	err := RedisDB.Set(ctx, key, value, 0).Err()
	return err
}

func Get(key string) (string, error) {
	val, err := RedisDB.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", errors.New("key not found")
	}

	return val, err
}

func Delete(key string) error {
	err := RedisDB.Del(ctx, key).Err()
	return err
}
