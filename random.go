package jwt

/*
import (
	"crypto/rand"
	"errors"
	"time"
)


func jwtTodayDate() (int64, error) {
	now := time.Now()
	secs := now.Unix()
	//fmt.Println("\nnow : ", secs)
	tm := time.Unix(secs, 0)
	fmt.Println(tm)

	return secs, nil
}

func secretGenerator(key string, date time.Time) string {
	secretkey := randomJwtSecret()
	today, _ := jwtTodayDate()
	secret := secretkey + string(today)
	//fmt.Println("the secret generated is ", secret)
	return secret
}

func randomJwtSecret() string {
	n := rand.Intn(len(jwtkeys))
	//fmt.Println("the random secret index picked is ", n)
	secret := jwtkeys[n]
	//fmt.Println("the random secret picked is ", secret)
	return secret
}
func randomKeyId() int {
	n := rand.Intn(len(jwtkeys))
	//fmt.Println("the random secret index picked is ", n)
	//secret := jwtkeys[n]
	//fmt.Println("the random secret picked is ", secret)
	return n
}

func jwtSecretFromKeyId(id int) (string, error) {
	//fmt.Println("key id : ", id)
	//fmt.Println("jwtkeys values ...")
	//for i := 0; i < len(jwtkeys); i++ {
	//	fmt.Println("i = ", i, " , key = ", jwtkeys[i])
	//}
	//fmt.Println("comparison")
	if id > len(jwtkeys)-1 {
		return "", errors.New("The Key Id is invalid sorry")
	} else {
		return jwtkeys[id], nil
	}
}
*/
