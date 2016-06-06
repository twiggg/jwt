package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"twiggg/packages/encryption"
)

func Validate(inputToken string, keypicker KeyPicker) (Jwtclaims, error) {
	/*
		-the token needs to contain an algo that is valide, "none" should be unvalidated.

		-uncode the token
		-read the head
		-check algo if none -> return ("",err)
		-else, if algo is valid, try to re-sign the token with the same algo, compare signatures
		-if signatures match -> return (claims,nil)
	*/
	c := Jwtclaims{}
	parts := strings.Split(inputToken, ".")
	if len(parts) != 3 {
		return c, errors.New("jwt validate: the token structure is invalid. Does not contain 3 parts separated by '.'.")
	}
	head := jwthead{}
	claims := Jwtclaims{}

	// json unmarshal the head
	decoded, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		s := fmt.Sprint("jwt validate base64 decode head:", err)
		return c, errors.New(s)
	}
	err = json.Unmarshal(decoded, &head)
	if err != nil {
		s := fmt.Sprint("jwt validate json unmarshall head:", err)
		return c, errors.New(s)
	}
	// json unmarshal the claims
	decoded, err = base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		s := fmt.Sprint("jwt validate base64 decode claims:", err)
		return c, errors.New(s)
	}
	err = json.Unmarshal(decoded, &claims)
	if err != nil {
		s := fmt.Sprint("jwt validate json unmarshall claims:", err)
		return c, errors.New(s)
	}
	//check if algo is valid
	if strings.ToLower(head.Alg) != "bcrypt" && strings.ToLower(head.Alg) != "hs256" {
		s := fmt.Sprint("jwt validate unvalid algorithm value")
		return c, errors.New(s)
	}
	//get the key
	key := []byte("")
	if keypicker == nil {
		key = []byte(jwtkeys[head.KeyId])
	} else {
		key, err = keypicker.keyValue(head.KeyId)
		if err != nil {
			s := fmt.Sprint("jwt validate could not get the key:", err)
			return c, errors.New(s)
		}
	}

	//compare signatures to verify if the token can be trusted
	//only 2 values accepted for the algorithm in this implementation: bcrypt or hs256
	switch head.Alg {
	case "bcrypt":
		//message string, salt byte, default cost
		//to get the salt (=the key) it is necessary to get the keyId and keyProvider
		//fmt.Println("bcrypt")
		outputToken, err := encryption.Hashbcrypt(strings.Join([]string{parts[0], parts[1]}, "."), key, 12)
		if err != nil {
			s := fmt.Sprint("jwt validate bcrypt:", err)
			return c, errors.New(s)
		}
		if bytes.Equal([]byte(inputToken), outputToken) {
			return c, errors.New("jwt validate: untrusted token")
		}
		return claims, nil
	case "hs256":
		outputToken, err := encryption.HashHS256(strings.Join([]string{parts[0], parts[1]}, "."), key)
		if err != nil {
			s := fmt.Sprint("jwt validate hs256:", err)
			return c, errors.New(s)
		}
		if bytes.Equal([]byte(inputToken), outputToken) {
			return c, errors.New("jwt validate: untrusted token")
		}
		return claims, nil
	default:
		return c, errors.New("jwt validate: the value of the algorithm is not valid.")
	}

}
