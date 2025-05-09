package models

type LoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	ExpiresIn    int64  `json:"expiresIn"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type LoginData struct {
	ClientID string `json:"clientId"`
	UserID   string `json:"userId"`
	State    string `json:"state"`
	Scope    string `json:"scope"`
}

type TokenRequest struct {
	Code         string `form:"code" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
	GrantType    string `form:"grant_type" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
}
