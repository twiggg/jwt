package jwt

import (
	"bytes"
	"errors"
	//"fmt"
	//"strings"
	"testing"
)

func TestKeySlicePickKey(t *testing.T) {
	k := []KeySlice{
		{"1a9s8n8", "1K9l89853"},
		{"abcdefg"},
	}
	//if k.valid
	//fmt.Println("len(keysplice):", len(k))
	tests := []struct {
		keys KeySlice
		err  error
	}{
		{k[0], nil},
		{k[1], nil},
		//{k[1], errors.New("jwt/keySlice.pickKey : no keys stored in this slice")},
	}
	//fmt.Println("len(tests):", len(tests))

	for _, v := range tests {
		//fmt.Println("test:", i)
		key, keyid, err := v.keys.pickKey()
		if v.err != err {
			t.Error("errors mismatch,", "expected:", v.err, "received:", err)
		} else {
			if !bytes.Equal(key, []byte(v.keys[keyid])) {
				t.Error("the key does not match any possible key")
			}
		}
	}
}

func TestGenerate(t *testing.T) {
	/*var liste keySlice
	liste = []string{"1a9s8n8", "1K9l89853"}*/
	liste := KeySlice{"1a9s8n8", "1K9l89853", "l2a9h0s1s8e8n", "aeiouy"}

	type parameters struct {
		keypicker   KeyPicker
		algo        string
		issuer      string
		username    string
		role        string
		accesslevel string
		audience    []string
		tokenId     string
	}
	tests := []struct {
		params parameters
		token  string
		erreur error
	}{
		{
			parameters{
				liste,
				"BcRYPT",
				"test.com",
				"@laahs",
				"standard",
				"private",
				[]string{"test.com"},
				"",
			},
			"",
			nil,
		},
		{
			parameters{
				nil,
				"BcRYPT",
				"test.com",
				"@laahs",
				"standard",
				"private",
				[]string{"test.com"},
				"",
			},
			"",
			errors.New("jwt.Generate: no valid KeyPicker provided"),
		},
		{
			parameters{
				KeySlice{},
				"BcRYPT",
				"test.com",
				"@laahs",
				"standard",
				"private",
				[]string{"test.com"},
				"",
			},
			"",
			errors.New("jwt.Generate: no valid KeyPicker provided"),
		},
		{
			parameters{
				KeySlice{"klk"},
				"BcRYPT",
				"test.com",
				"@laahs",
				"standard",
				"private",
				[]string{"test.com"},
				"",
			},
			"",
			nil,
		},
	}

	//fmt.Printf("tests : \n%v\n", tests)

	for index, v := range tests {
		_, err := Generate(v.params.keypicker, v.params.algo, v.params.issuer, v.params.username, v.params.role, v.params.accesslevel, v.params.audience, v.params.tokenId)
		//fmt.Println(index, token)
		if v.erreur != nil && err != nil {
			if v.erreur.Error() != err.Error() {
				t.Error("cas", index, ": errors mismatch,", "expected:", v.erreur, "received:", err)
			}
		} else if v.erreur == nil && err == nil {

		} else {
			t.Error("cas", index, ": errors mismatch,", "expected:", v.erreur, "received:", err)
		}
	}
}
