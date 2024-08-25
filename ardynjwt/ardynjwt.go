package ardynjwt

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

//-------------------------------------------------------------

type ArdynJwt struct {
	privateKey []byte
	publicKey  []byte
}

// https://www.iana.org/assignments/jwt/jwt.xhtml#IESG
type TokenUserData struct {
	UserId string   `json:"userid"`
	Roles  []string `json:"roles"`
}

//-------------------------------------------------------------

func NewJwt() (jwt *ArdynJwt) {

	jwt = &ArdynJwt{}

	return

}

//-------------------------------------------------------------

func (jwt *ArdynJwt) LoadPrivateKey(privateKeyFilename string) (err error) {

	log.Println("Loading private key ", privateKeyFilename)

	jwt.privateKey, err = jwt.loadKey(privateKeyFilename)

	if err != nil {

		log.Println("Error loading private key ", privateKeyFilename)

	}

	log.Println("Loaded private key ", privateKeyFilename)

	return

}

//-------------------------------------------------------------

func (jwt *ArdynJwt) LoadPublicKey(publicKeyFilename string) (err error) {

	log.Println("Loading public key ", publicKeyFilename)

	jwt.publicKey, err = jwt.loadKey(publicKeyFilename)

	if err != nil {

		log.Println("Error loading public key ", publicKeyFilename)

	}

	log.Println("Loaded public key ", publicKeyFilename)

	return

}

// -------------------------------------------------------------

func (jwt *ArdynJwt) loadKey(filename string) (data []byte, err error) {

	data, err = os.ReadFile(filename)

	if err != nil {

		log.Println("Error reading key file ", filename)

		return nil, err

	}

	return

}

//-------------------------------------------------------------

func (j *ArdynJwt) Create(ttl time.Duration, tokenData TokenUserData) (string, error) {

	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)

	if err != nil {

		return "", fmt.Errorf("create: parse key: %w", err)

	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)

	//claims["usr"] = tokenData           // Our custom data.
	claims["userid"] = tokenData.UserId
	claims["roles"] = tokenData.Roles
	claims["exp"] = now.Add(ttl).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()          // The time at which the token was issued.
	claims["nbf"] = now.Unix()          // The time before which the token must be disregarded.

	// User data payload

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)

	if err != nil {

		return "", fmt.Errorf("create: sign token: %w", err)

	}

	return token, nil

}

//-------------------------------------------------------------

func (j *ArdynJwt) Validate(token string) (tokenData TokenUserData, err error) {

	tokenData = TokenUserData{}

	err = nil

	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)

	if err != nil {

		log.Println("Error validating: parse key: %w", err)

		return

	}

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {

		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {

			return tokenData, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])

		}

		return key, nil

	})

	if err != nil {

		log.Println("Error validating: parse token: %w", err)

		return

	}

	claims, ok := tok.Claims.(jwt.MapClaims)

	if !ok || !tok.Valid {

		log.Println("Invalid token")

		err = fmt.Errorf("invalid token")

		return

	}

	tokenData.UserId = claims["userid"].(string)

	roles := claims["roles"].([]interface{})

	tokenData.Roles = make([]string, len(roles))

	for i, role := range roles {
		tokenData.Roles[i] = role.(string)
	}

	return

}

// -------------------------------------------------------------

func (jwt *ArdynJwt) GetPrivateKey() []byte {

	return jwt.privateKey

}

//-------------------------------------------------------------

func (jwt *ArdynJwt) GetPublicKey() []byte {

	return jwt.publicKey

}

//-------------------------------------------------------------
