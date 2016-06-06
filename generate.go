package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"
	"twiggg/packages/encryption"
)

type jwthead struct {
	Typ   string `json:"typ"` //JWT
	Alg   string `json:"alg"` // IMPORTANT : if alg=none, JWT needs to be declared unvalid
	KeyId int    `json:"kid"` // key int identifier of the randomly selected key from the keys list
}

type Jwtclaims struct {
	Iss string     `json:"iss"` //name of issuer
	Iat int64      `json:"iat"` //issued at time
	Exp int64      `json:"exp"` //expiration time
	Nbf int64      `json:"nbf"` //cant be used before this date
	Qsh string     `json:"qsh"` //query string hash
	Sub jwtcontext `json:"sub"` //subject = user
	Aud []string   `json:"aud"` //audience of the token
	Jti string     `json:"jti"` //jwt token unique identifier, in order to prevent replay attack. Used for one time use tokens.
}

type jwtcontext struct {
	Username string `json:"username"` //alias of the user
	//Userid         string `json:"userid"`         //user id used for shortcut access to db and user's perso space
	Role           string `json:"role"`           //admin,test,standard,dev
	AccessLevel    string `json:"accesslevel"`    //access level grants access to certain endpoints
	LastConnection int64  `json:"lastconnection"` //time of last connection
	//-> private means access to personal space + public pages. Can modify own info
	//-> public means only access to public pages
	//-> admin means access to everything and permissions to create read update delete
	//-> analytics
	//-> test
}

//encoding
//encodedString := base64.URLEncoding.EncodeToString([]byte(initialString))
//encodedString := base64.StdEncoding.EncodeToString([]byte(initialString))
//decoding
//decodedString, err := base64.URLEncoding.DecodeString(encodedString)
//decodedString, err := base64.StdEncoding.DecodeString(encodedString)

type KeyPicker interface {
	pickKey() ([]byte, int, error)
	valid() bool
	keyValue(keyId int) ([]byte, error)
}

type KeySlice []string

var jwtkeys KeySlice = []string{"1K9l89853", "1a9s8n8", "l2a9h0s1s8e8n", "aeiouy"}

func (k KeySlice) pickKey() ([]byte, int, error) {
	if len(k) > 0 {
		n := rand.Intn(len(k))
		key := k[n]
		return []byte(key), n, nil
	} else {
		return nil, 0, errors.New("jwt/keySlice.pickKey : no keys stored in this slice")
	}

}

func (k KeySlice) valid() bool {
	if len(k) == 0 {
		return false
	} else {
		for _, v := range k {
			if len(v) == 0 {
				return false
			}
		}
		return true
	}

}

func (k KeySlice) keyValue(keyId int) ([]byte, error) {
	if len(k) < (keyId + 1) {
		return []byte(""), errors.New("KeySlice.KeyValue: index out of range.")
	} else {
		return []byte(k[keyId]), nil
	}

}

//-----------------------------------------------------------------------
func New(keypicker KeyPicker, algorithm string, issuer string, username string, role string, accesslevel string, audience []string, tokenId string) (string, error) {
	//keypicker2 := new(KeyPicker)
	//var keypicker2 KeyPicker
	//fmt.Println("valid keypicker:", keypicker.valid())
	if keypicker == nil || !keypicker.valid() {
		//fmt.Println("jwt.Generate: keypicker was nil, changed to default in memory keyPicker")
		//keypicker2 = jwtkeys
		return "", errors.New("jwt.Generate: no valid KeyPicker provided")
	} /*else {
		keypicker2 = keypicker
	}*/
	// 1) head
	//generate head
	head := jwthead{}
	head.Typ = "JWT"
	switch strings.ToLower(algorithm) {
	case "bcrypt":
		head.Alg = "bcrypt"
	case "hs256":
		head.Alg = "hs256"
	default:
		head.Alg = "bcrypt"
	}
	//pick key
	key, keyid, err := keypicker.pickKey()
	if err != nil {
		return "", errors.New("jwt.generate : could not pick a key")
	}
	head.KeyId = keyid
	//fmt.Println(head)
	//jsonmarshal head
	json_h, err := json.Marshal(head)
	//fmt.Println(json_h)
	if err != nil {
		//fmt.Println("error : ", err)
		s := fmt.Sprint("jwt.generate : could not generate json head, %v", err.Error())
		return "", errors.New(s)
	}
	//encode head
	encodedHead := base64.URLEncoding.EncodeToString([]byte(json_h))
	//fmt.Println(encodedHead)
	//2) claims
	//generate claims
	claims := Jwtclaims{}
	claims.Iss = issuer
	claims.Iat = time.Now().Unix()
	claims.Exp = time.Unix(claims.Iat, 0).Add(time.Second * 60 * 60 * 24 * 3).Unix() // 3days of validity
	claims.Qsh = ""
	context := jwtcontext{}
	context.Username = username
	context.Role = role
	context.AccessLevel = accesslevel
	claims.Sub = context
	claims.Aud = audience
	claims.Jti = tokenId
	//json marshal claims
	//fmt.Println(claims)
	json_c, err := json.Marshal(claims)
	//fmt.Println(json_c)
	if err != nil {
		//fmt.Println("error : ", err)
		s := fmt.Sprint("jwt.generate : could not generate json claims, %v", err.Error())
		return "", errors.New(s)
	}
	//encode claims
	encodedClaims := base64.URLEncoding.EncodeToString([]byte(json_c))
	//fmt.Println(encodedClaims)

	//3) signature
	//sign the token (encryption)
	signingInput := fmt.Sprint(encodedHead, ".", encodedClaims)
	signaturebytes := []byte{}
	var err2 error = nil
	switch head.Alg {
	case "bcrypt":
		//encryption.GenerateRandomBytes(n)
		signaturebytes, err2 = encryption.Hashbcrypt(signingInput, key, 12)
		if err != nil {
			s := fmt.Sprint("jwt.generate : could not sign, %v", err2.Error())
			return "", errors.New(s)
		}
	case "hs256":
		signaturebytes, err2 = encryption.HashHS256(signingInput, key)
		if err != nil {
			s := fmt.Sprint("jwt.generate : could not sign, %v", err2.Error())
			return "", errors.New(s)
		}
	default:
		signaturebytes, err2 = encryption.Hashbcrypt(signingInput, key, 12)
		if err != nil {
			s := fmt.Sprint("jwt.generate : could not sign, %v", err2.Error())
			return "", errors.New(s)
		}
	}
	//encode signature
	encodedSignature := base64.URLEncoding.EncodeToString(signaturebytes)

	//4) token
	jwtToken := fmt.Sprint(signingInput, ".", encodedSignature)
	return jwtToken, nil

}

func Refresh() {

}
