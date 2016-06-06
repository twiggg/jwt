package jwt

import (
	"errors"
	//"fmt"
	"strings"
	"testing"
)

func TestJwtValidation(t *testing.T) {
	//fmt.Println("test jwt validation started ...")
	// token 1
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJiY3J5cHQiLCJraWQiOjN9.eyJpc3MiOiJ0ZXN0LmNvbSIsImlhdCI6MTQ0NDI5OTU0NywiZXhwIjoxNDQ0NTU4NzQ3LCJuYmYiOjAsInFzaCI6IiIsInN1YiI6eyJ1c2VybmFtZSI6IkBsYWFocyIsInJvbGUiOiJzdGFuZGFyZCIsImFjY2Vzc2xldmVsIjoicHJpdmF0ZSIsImxhc3Rjb25uZWN0aW9uIjowfSwiYXVkIjpbInRlc3QuY29tIl0sImp0aSI6IiJ9.JDJhJDEwJHdsbnJTMHVjZmtzS2lhc3FOZ3F6eXUvMFFHY0p1QzVackRRbzkudkIuZ1JaOHl4LmpENjZD
	// token 2
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJiY3J5cHQiLCJraWQiOjB9.eyJpc3MiOiJ0ZXN0LmNvbSIsImlhdCI6MTQ0NDI5OTU0NywiZXhwIjoxNDQ0NTU4NzQ3LCJuYmYiOjAsInFzaCI6IiIsInN1YiI6eyJ1c2VybmFtZSI6IkBsYWFocyIsInJvbGUiOiJzdGFuZGFyZCIsImFjY2Vzc2xldmVsIjoicHJpdmF0ZSIsImxhc3Rjb25uZWN0aW9uIjowfSwiYXVkIjpbInRlc3QuY29tIl0sImp0aSI6IiJ9.JDJhJDEwJGVwbE9rUDluTG5xMksweUsyQ3ZpNmU0SjgyMkFyTFFUbGFkR0NtUkttdElVLnRaUTBINWNx

	token1 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJiY3J5cHQiLCJraWQiOjN9.eyJpc3MiOiJ0ZXN0LmNvbSIsImlhdCI6MTQ0NDI5OTU0NywiZXhwIjoxNDQ0NTU4NzQ3LCJuYmYiOjAsInFzaCI6IiIsInN1YiI6eyJ1c2VybmFtZSI6IkBsYWFocyIsInJvbGUiOiJzdGFuZGFyZCIsImFjY2Vzc2xldmVsIjoicHJpdmF0ZSIsImxhc3Rjb25uZWN0aW9uIjowfSwiYXVkIjpbInRlc3QuY29tIl0sImp0aSI6IiJ9.JDJhJDEwJHdsbnJTMHVjZmtzS2lhc3FOZ3F6eXUvMFFHY0p1QzVackRRbzkudkIuZ1JaOHl4LmpENjZD"
	token2 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJiY3J5cHQiLCJraWQiOjB9.eyJpc3MiOiJ0ZXN0LmNvbSIsImlhdCI6MTQ0NDI5OTU0NywiZXhwIjoxNDQ0NTU4NzQ3LCJuYmYiOjAsInFzaCI6IiIsInN1YiI6eyJ1c2VybmFtZSI6IkBsYWFocyIsInJvbGUiOiJzdGFuZGFyZCIsImFjY2Vzc2xldmVsIjoicHJpdmF0ZSIsImxhc3Rjb25uZWN0aW9uIjowfSwiYXVkIjpbInRlc3QuY29tIl0sImp0aSI6IiJ9.JDJhJDEwJGVwbE9rUDluTG5xMksweUsyQ3ZpNmU0SjgyMkFyTFFUbGFkR0NtUkttdElVLnRaUTBINWNx"
	token3 := strings.Join([]string{token1, token2}, ".")
	sp := strings.Split(token1, ".")
	token4 := strings.Join([]string{sp[0], sp[1]}, ".")

	type input struct {
		token     string
		keypicker KeyPicker
	}
	type output struct {
		claims Jwtclaims
		err    error
	}

	tests := []struct {
		data     input
		expected output
	}{
		{
			input{token1, nil},
			output{Jwtclaims{}, nil},
		},
		{
			input{token2, nil},
			output{Jwtclaims{}, nil},
		},
		{
			input{token3, nil},
			output{Jwtclaims{}, errors.New("jwt validate: the token structure is invalid. Does not contain 3 parts separated by '.'.")},
		},
		{
			input{token4, nil},
			output{Jwtclaims{}, errors.New("jwt validate: the token structure is invalid. Does not contain 3 parts separated by '.'.")},
		},
	}

	for _, v := range tests {
		claims, err := Validate(v.data.token, v.data.keypicker)
		//compare errors
		if v.expected.err != nil && err != nil {
			if v.expected.err.Error() != err.Error() {
				t.Error("errors don't match,", "expected:", v.expected.err, "received:", err)
			}
		} else if v.expected.err == nil && err == nil {

		} else {
			t.Error("errors don't match,", "expected:", v.expected.err, "received:", err)
		}

		if err == nil && claims.Qsh != "" {
			t.Error("validation should have return an empty claim, received:", claims)
		}

	}
}
