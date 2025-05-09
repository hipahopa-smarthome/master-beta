package repository

import (
	"devices-api/models"
	"gorm.io/gorm"
)

type DevicesRepo struct {
	db *gorm.DB
}

func NewDevicesRepo(db *gorm.DB) *DevicesRepo {
	return &DevicesRepo{db: db}
}

func (r *DevicesRepo) GetDevicesByUserId(userID string) ([]models.Device, error) {
	var devices []models.Device

	if err := r.db.
		Preload("Capabilities").
		Preload("Properties").
		Where("user_id = ?", userID).
		Find(&devices).Error; err != nil {
		return nil, err
	}

	return devices, nil
}

func (r *DevicesRepo) GetDeviceById(id string) (*models.Device, error) {
	var device models.Device

	if err := r.db.
		Preload("Capabilities").
		Preload("Properties").
		Where("id = ?", id).
		First(&device).Error; err != nil {
		return nil, err
	}

	return &device, nil
}

func (r *DevicesRepo) GetDevicesByIds(ids []string) ([]models.Device, error) {
	var devices []models.Device

	if err := r.db.
		Preload("Capabilities").
		Preload("Properties").
		Where("id IN ?", ids).
		Find(&devices).Error; err != nil {
		return nil, err
	}

	return devices, nil
}

func (r *DevicesRepo) SaveOrUpdateDevice(device *models.Device) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(device).Error; err != nil {
			return err
		}

		if err := tx.Model(device).Association("Capabilities").Replace(device.Capabilities); err != nil {
			return err
		}

		return nil
	})
	//
	//if err := r.db.Save(device).Error; err != nil {
	//	return err
	//}
	//
	//if err := r.db.Model(device).Association("Capabilities").Replace(device.Capabilities); err != nil {
	//	return err
	//}

	//for _, capability := range device.Capabilities {
	//	if err := r.db.Save(capability).Error; err != nil {
	//		return err
	//	}
	//}
}

func (r *DevicesRepo) UpdateCapabilityStateByDeviceIdAndType(deviceId string, capabilityType string, newState []byte) error {
	return r.db.
		Model(&models.Capability{}).
		Where("device_id = ? AND type = ?", deviceId, capabilityType).
		Update("state", newState).
		Error
}
