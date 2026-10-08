package db

import (
	"log"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Init 打开 SQLite 并自动迁移业务表
func Init(path string) *gorm.DB {
	var err error
	DB, err = gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("打开业务数据库失败: %v", err)
	}
	if err := DB.AutoMigrate(&BusinessUser{}, &BusinessSession{}); err != nil {
		log.Fatalf("业务数据库迁移失败: %v", err)
	}
	return DB
}

// Env 读取环境变量，带默认值
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
