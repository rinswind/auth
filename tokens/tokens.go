package tokens

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	uuid "github.com/satori/go.uuid"
)

// TokenDetails represents info
type TokenDetails struct {
	userID uint64

	// Access token
	AccessToken   string
	AccessUUID    string
	AccessExpires int64

	// Refresh token
	RefreshToken   string
	RefreshUUID    string
	RefreshExpires int64
}

type AuthReader struct {
	Redis *redis.Client

	ATSecret string
	RTSecret string
}

type AuthWriter struct {
	Redis *redis.Client

	ATSecret string
	ATExpiry time.Duration

	RTSecret string
	RTExpiry time.Duration
}

// CreateToken makes a new token for a given user
func (aw *AuthWriter) CreateToken(userID uint64) (*TokenDetails, error) {
	td := &TokenDetails{userID: userID}

	var err error

	// Creating Access Token
	td.AccessExpires = time.Now().Add(aw.ATExpiry).Unix()
	td.AccessUUID = uuid.NewV4().String()

	atClaims := jwt.MapClaims{}
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["user_id"] = userID
	atClaims["exp"] = td.AccessExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(aw.ATSecret))
	if err != nil {
		return nil, err
	}

	// Creating Refresh Token
	td.RefreshExpires = time.Now().Add(aw.RTExpiry).Unix()
	td.RefreshUUID = uuid.NewV4().String()

	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userID
	rtClaims["exp"] = td.RefreshExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(aw.RTSecret))
	if err != nil {
		return nil, err
	}

	return td, nil
}

// CreateAuth records the login details
func (aw *AuthWriter) CreateAuth(td *TokenDetails) error {
	at := time.Unix(td.AccessExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RefreshExpires, 0)
	now := time.Now()

	userIDStr := strconv.FormatUint(td.userID, 10)

	var err error

	err = aw.Redis.Set(context.Background(), td.AccessUUID, userIDStr, at.Sub(now)).Err()
	if err != nil {
		return err
	}
	err = aw.Redis.Set(context.Background(), td.RefreshUUID, userIDStr, rt.Sub(now)).Err()
	if err != nil {
		return err
	}
	return nil
}

// DeleteAuth destroys a users's login
// TODO Require the "access_uuid" instead? This API models Authentication not as a JWT token, but rather as a map of claims
func (aw *AuthWriter) DeleteAuth(claims map[string]interface{}) (uint64, error) {
	atUUID, ok := claims["access_uuid"].(string)
	if !ok {
		return 0, fmt.Errorf("No %v claim in token", "access_uuid")
	}

	userID, err := aw.Redis.Del(context.Background(), atUUID).Uint64()
	if err != nil {
		return 0, err
	}
	return userID, nil
}

// ReadAuth obtains a cached user login
func (ar *AuthReader) ReadAuth(tokenStr string) (map[string]interface{}, error) {
	claims, err := decodeToken(tokenStr, ar.ATSecret)
	if err != nil {
		return nil, err
	}

	atUUID, ok := claims["access_uuid"].(string)
	if !ok {
		return nil, fmt.Errorf("No %v claim in token", "access_uuid")
	}

	err = ar.Redis.Get(context.Background(), atUUID).Err()
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func decodeToken(encoded string, key string) (map[string]interface{}, error) {
	token, err := jwt.Parse(encoded, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(key), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("Token invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("Bad claims type %T", claims)
	}
	return claims, nil
}
