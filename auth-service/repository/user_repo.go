package repository

import (
	"auth-server/db"
	"auth-server/models"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"time"
)

type UserRepo struct {
	db           *gorm.DB
	redisClients *db.RedisClients
}

func NewUserRepo(db *gorm.DB, redisClients *db.RedisClients) *UserRepo {
	return &UserRepo{db: db, redisClients: redisClients}
}

func (r *UserRepo) CreateUser(req *models.RegistrationUser) (*models.User, error) {
	userUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("error generating userUuid: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user := &models.User{
		ID:       userUuid.String(),
		Email:    req.Email,
		Name:     req.Name,
		Password: string(hashedPassword),
	}
	result := r.db.Create(user).First(&user)
	if result.Error != nil {
		return nil, fmt.Errorf("cannot create user: %s\n", result.Error)
	}
	return user, nil
}

func (r *UserRepo) UpdateUserPassword(userID string, hashedPassword string) error {
	result := r.db.Model(&models.User{}).
		Where("id = ?", userID).
		Update("Password", hashedPassword)

	if result.Error != nil {
		return fmt.Errorf("failed to update password: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (r *UserRepo) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	result := r.db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func (r *UserRepo) GetUserById(id string) (*models.User, error) {
	var user models.User
	result := r.db.Where("id = ?", id).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func (r *UserRepo) SetLoginDataByCode(code string, clientId string, userId string, state string, scope string) error {
	ctx := context.Background()

	loginData := models.LoginData{
		ClientID: clientId,
		UserID:   userId,
		State:    state,
		Scope:    scope,
	}

	data, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("failed to marshal login data: %w", err)
	}

	err = r.redisClients.DB0.Set(ctx, code, data, time.Minute*15).Err()
	if err != nil {
		return fmt.Errorf("failed saving code to redis: %w", err)
	}

	return nil
}

func (r *UserRepo) GetLoginDataByCode(code string) (*models.LoginData, error) {
	ctx := context.Background()

	data, err := r.redisClients.DB0.Get(ctx, code).Result()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("code not found in redis")
	} else if err != nil {
		return nil, fmt.Errorf("failed getting code data from redis: %w", err)
	}

	var loginData models.LoginData
	err = json.Unmarshal([]byte(data), &loginData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal login data: %w", err)
	}

	return &loginData, nil
}

func (r *UserRepo) DeleteLoginDataByCode(code string) error {
	ctx := context.Background()

	err := r.redisClients.DB0.Del(ctx, code).Err()
	if err != nil {
		return fmt.Errorf("failed deleting code from redis: %w", err)
	}

	return nil
}

func (r *UserRepo) SetEmailConfirmationCode(code string, email string, expiresAt time.Duration) error {
	ctx := context.Background()

	err := r.redisClients.DB1.Set(ctx, code, email, expiresAt).Err()
	if err != nil {
		return fmt.Errorf("failed saving confirmation code to redis: %w", err)
	}

	return nil
}

func (r *UserRepo) CheckCodeWithEmail(code string, email string) (bool, error) {
	ctx := context.Background()

	emailInDb, err := r.redisClients.DB1.Get(ctx, code).Result()
	if err != nil {
		return false, err
	}

	return emailInDb == email, nil
}

func (r *UserRepo) SetUserStatusConfirmed(email string) error {
	return r.db.
		Model(&models.User{}).
		Where("email = ?", email).
		Update("confirmed", true).Error
}

func (r *UserRepo) SetResetPasswordCode(code string, email string) error {
	ctx := context.Background()

	err := r.redisClients.DB1.Set(ctx, code, email, time.Minute*15).Err()
	if err != nil {
		return err
	}

	return nil
}

func (r *UserRepo) GetEmailByResetPasswordCode(code string) (string, error) {
	ctx := context.Background()

	email, err := r.redisClients.DB1.Get(ctx, code).Result()
	if err != nil {
		return "", err
	}

	return email, nil
}

func (r *UserRepo) DeleteResetPasswordCode(code string) error {
	ctx := context.Background()

	err := r.redisClients.DB1.Del(ctx, code).Err()
	if err != nil {
		return fmt.Errorf("failed deleting code from redis: %w", err)
	}

	return nil
}
