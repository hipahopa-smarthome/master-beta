package models

import "time"

type ManufacturedDevice struct {
	ID         string    `gorm:"type:uuid;primary_key" json:"id"`
	MacAddress *string   `json:"mac_address"`
	CreatedAt  time.Time `json:"created_at"`
}
