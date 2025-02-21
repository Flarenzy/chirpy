package auth

import (
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckPasswordHash(t *testing.T) {
	data := []string{"password1", "password2", "password3"}
	for _, password := range data {
		hashedPW, err := HashPassword(password)
		if err != nil {
			t.Errorf("Error hashing password: %v", err)
			continue
		}
		if !CheckPasswordHash(password, hashedPW) {
			t.Errorf("Passwords don't match, pw: %v, hash: %v", password, hashedPW)
		}
	}
}

func TestMakeJWT(t *testing.T) {
	t.Parallel()
	testData := []struct {
		testName    string
		id          uuid.UUID
		tokenSecret string
		expiration  time.Duration
	}{
		{"TestMakeJWT", uuid.New(), "SecretToken", time.Minute},
	}
	for _, data := range testData {
		t.Run(data.testName, func(t *testing.T) {
			_, err := MakeJWT(data.id, data.tokenSecret, data.expiration)
			if err != nil {
				t.Errorf("Error creating JWT: %v", err)
				t.FailNow()
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	t.Parallel()
	testData := []struct {
		testName    string
		id          uuid.UUID
		tokenSecret string
		expiration  time.Duration
	}{
		{"TestValidateJWT", uuid.New(), "SecretToken", time.Hour},
	}
	for _, data := range testData {
		t.Run(data.testName, func(t *testing.T) {
			jwt, err := MakeJWT(data.id, data.tokenSecret, data.expiration)
			if err != nil {
				t.Errorf("Error creating JWT: %v", err)
				t.FailNow()
			}
			validateJWT, err := ValidateJWT(jwt, data.tokenSecret)
			if err != nil {
				t.Errorf("Error validating JWT: %v", err)
				t.FailNow()
			}
			if validateJWT != data.id {
				t.Errorf("ID does not match, validateJWT: %v, validateJWT: %v", data.id, validateJWT)
			}
		})
	}
}

func TestExpiredToken(t *testing.T) {
	t.Parallel()
	testData := []struct {
		testName    string
		id          uuid.UUID
		tokenSecret string
		expiration  time.Duration
	}{
		{"TestExpiredToken", uuid.New(), "SecretToken", time.Second},
	}
	for _, data := range testData {
		t.Run(data.testName, func(t *testing.T) {
			jwt, err := MakeJWT(data.id, data.tokenSecret, data.expiration)
			if err != nil {
				t.Errorf("Error creating JWT: %v", err)
			}
			_, err = ValidateJWT(jwt, data.tokenSecret)
			if err != nil {
				t.Errorf("Token should be valid before expiring: %v", err)
			}
			time.Sleep(data.expiration * 2)
			_, err = ValidateJWT(jwt, data.tokenSecret)
			if err != nil {
				if err.Error() != "token has invalid claims: token is expired" {
					t.Errorf("Expected that toket has expired: %v", err)
				}
			}
		})
	}
}

func TestWrongTokenSecret(t *testing.T) {
	t.Parallel()
	testData := []struct {
		testName    string
		id          uuid.UUID
		tokenSecret string
		expiration  time.Duration
	}{
		{"TestWrongTokenSecret", uuid.New(), "SecretToken", time.Hour},
	}
	for _, data := range testData {
		t.Run(data.testName, func(t *testing.T) {
			jwt, err := MakeJWT(data.id, data.tokenSecret, data.expiration)
			if err != nil {
				t.Errorf("Error creating JWT: %v", err)
			}
			_, err = ValidateJWT(jwt, "WrongTokenSecret")
			if err != nil {
				if err.Error() != "token signature is invalid: signature is invalid" {
					t.Errorf("Expected that the token secret is wrong %v", err)
				}
			}
		})
	}
	_, err := ValidateJWT("not.a.token", "WrongTokenSecret")
	if err != nil {
		if err.Error() != "token is malformed: could not JSON decode header: invalid character '\\u009e' looking for beginning of value" {
			t.Errorf("Expected that the token is malformed %v", err)
		}
	}
}

func TestGetBearerToken(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer   secret   ")
	token, err := GetBearerToken(r.Header)
	if err != nil {
		t.Errorf("Error getting token: %v", err)
		return
	}
	if token != "secret" {
		t.Errorf("Expected token to be 'secret', got %v", token)
	}
}

func TestGetBearerTokenInvalid(t *testing.T) {
	t.Parallel()
	testData := []struct {
		testName    string
		tokenValue  string
		expectedErr string
	}{
		{"TestGetBearerTokenNoSecret", "", "authorization header not found"},
		{"TestGetBearerTokenInvalidSecret", "Some invalid token", "invalid token"},
		{"TestGetBearerTokenOnlyWhiteSpace", "\n \t\n", "invalid token"},
	}
	for _, data := range testData {
		t.Run(data.testName, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", data.tokenValue)
			_, err := GetBearerToken(r.Header)
			if err != nil {
				if err.Error() != data.expectedErr {
					t.Errorf("Expected: %v got: %v", data.expectedErr, err)
				}
			}

		})
	}
}
