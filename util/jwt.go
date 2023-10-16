package util

import (
	"fmt"
	"github.com/go-sonic/sonic/consts"
	"github.com/go-sonic/sonic/log"
	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
	"time"
)

type CustomClaims struct {
	UserID int32 `json:"user_id"`
	//Username string `json:"username"`
	jwt.StandardClaims
}

func GenerateToken(userID int32, secret string) (string, error) {
	claims := &CustomClaims{
		UserID: userID,
		//Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * consts.AccessTokenExpiredSeconds).Unix(), // Token 有效期为 24 小时
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ParseToken(tokenString string, secret string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	log.Error("invalid token", zap.Error(err))
	return nil, err
}
