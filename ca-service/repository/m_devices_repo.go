package repository

import (
	"ca-service/db"
	"ca-service/models"
	"context"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
	"time"
)

type ManufacturedDevicesRepo struct {
	database *gorm.DB
	certDB   *db.NamespacedRedis
}

func NewManufacturedDevicesRepo(database *gorm.DB, client *redis.Client) *ManufacturedDevicesRepo {
	certDB := db.NewNamespacedRedis(client, "certs")

	return &ManufacturedDevicesRepo{
		database: database,
		certDB:   certDB,
	}
}

func (r *ManufacturedDevicesRepo) GetDeviceById(id string) (*models.ManufacturedDevice, error) {
	var device models.ManufacturedDevice

	if err := r.database.
		Where("id = ?", id).
		First(&device).Error; err != nil {
		return nil, err
	}

	return &device, nil
}

func (r *ManufacturedDevicesRepo) GetDevicesByIds(ids []string) ([]models.ManufacturedDevice, error) {
	var devices []models.ManufacturedDevice

	if err := r.database.
		Where("id IN ?", ids).
		Find(&devices).Error; err != nil {
		return nil, err
	}

	return devices, nil
}

func (r *ManufacturedDevicesRepo) GetDeviceByMacAddress(macAddress string) (*models.ManufacturedDevice, error) {
	var device models.ManufacturedDevice

	if err := r.database.
		Where("mac_address = ?", macAddress).
		First(&device).Error; err != nil {
		return nil, err
	}

	return &device, nil
}

func (r *ManufacturedDevicesRepo) SetCertCode(code string, macAddress string) error {
	ctx := context.Background()

	err := r.certDB.Set(ctx, code, macAddress, time.Minute*15)
	if err != nil {
		return err
	}

	return nil
}

func (r *ManufacturedDevicesRepo) GetCertCode(code string) (string, error) {
	ctx := context.Background()

	macAddress, err := r.certDB.Get(ctx, code)
	if err != nil {
		return "", err
	}

	return macAddress, nil
}

func (r *ManufacturedDevicesRepo) DeleteCertCode(code string) error {
	ctx := context.Background()

	err := r.certDB.Del(ctx, code)
	if err != nil {
		return err
	}

	return nil
}
