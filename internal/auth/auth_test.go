package auth

import (
        "errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectingError error
	}{
		{
			name:          "Valid API Key",
			authHeader:    "ApiKey my-secret-key",
			expectedKey:   "my-secret-key",
			expectingError: nil,
		},
		{
			name:          "Missing Authorization Header",
			authHeader:    "",
			expectedKey:   "",
			expectingError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Invalid Authorization Format",
			authHeader:    "Bearer my-secret-key",
			expectedKey:   "",
			expectingError: errors.New("malformed authorization header"),
		},
		{
			name:          "Missing ApiKey Token",
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectingError: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			apiKey, err := GetAPIKey(headers)

			if err != nil && tc.expectingError == nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if err == nil && tc.expectingError != nil {
				t.Errorf("Expected error %v but got none", tc.expectingError)
			}

			if apiKey != tc.expectedKey {
				t.Errorf("Expected API key %q but got %q", tc.expectedKey, apiKey)
			}
		})
	}
}

