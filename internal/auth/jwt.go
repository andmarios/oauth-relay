package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims extends standard JWT claims with relay-specific fields.
type Claims struct {
	jwt.RegisteredClaims
	Email      string `json:"email,omitempty"`
	Role       string `json:"role,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
	TokenType  string `json:"token_type"` // "access" or "refresh"
}

// JWTService handles JWT issuance and validation using HS256.
type JWTService struct {
	signingKey      []byte
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// NewJWTService creates a new JWT service with the given configuration.
func NewJWTService(signingKey, issuer string, accessTTL, refreshTTL time.Duration) *JWTService {
	return &JWTService{
		signingKey:      []byte(signingKey),
		issuer:          issuer,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

// IssueAccessToken creates a short-lived access token with user claims.
func (s *JWTService) IssueAccessToken(userID, email, role, providerID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			ID:        uuid.NewString(),
		},
		Email:      email,
		Role:       role,
		ProviderID: providerID,
		TokenType:  "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.signingKey)
}

// IssueRefreshToken creates a long-lived refresh token with minimal claims.
// Returns the signed token string and the jti (for revocation tracking).
func (s *JWTService) IssueRefreshToken(userID string) (string, string, error) {
	now := time.Now()
	jti := uuid.NewString()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshTokenTTL)),
			ID:        jti,
		},
		TokenType: "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.signingKey)
	return signed, jti, err
}

// ValidateToken parses and validates a JWT, returning the claims.
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signingKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}
