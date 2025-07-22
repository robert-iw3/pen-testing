package db

import (
	"api/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var ORM *gorm.DB

func Init(dbName string) error {
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		return err
	}

	if err := db.AutoMigrate(
		&models.Agent{},
		&models.Message{},
	); err != nil {
		return err
	}

	ORM = db

	return nil
}
