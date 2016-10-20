package kms

import (
	"errors"

	"github.com/meltwater/secretary/box"
)

const mockKmsKey = `Q1PuWtB1E7F1sLpvfBGjL+ZuH+fSCOvMDqTyRQE4GTg=`

type MockKmsClient struct {
}

func NewMockKmsClient() *MockKmsClient {
	return &MockKmsClient{}
}

func (k *MockKmsClient) GenerateDataKey(keyID string) (*[32]byte, []byte, error) {
	if keyID != "123" {
		return nil, nil, errors.New("Expected keyID=123")
	}

	key, err := box.Decode(mockKmsKey)
	if err != nil {
		return nil, nil, err
	}

	dataKey, err := box.AsKey(key)
	if err != nil {
		return nil, nil, err
	}

	return dataKey, []byte(mockKmsKey), nil
}

func (k *MockKmsClient) Decrypt(data []byte) (*[32]byte, error) {
	key, err := box.Decode(string(data))
	if err != nil {
		return nil, err
	}

	dataKey, err := box.AsKey(key)
	if err != nil {
		return nil, err
	}

	return dataKey, nil
}
