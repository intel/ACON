package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

const (
	UserRuntimeDir = "/run/user"
	AuthTableFile  = "tokens.json"
)

// map vmid to associated access token
type AuthTable map[string]string

var authTableMutex sync.Mutex

func getUserAuthTable(uid string) (AuthTable, error) {
	records, err := os.ReadFile(filepath.Join(UserRuntimeDir, uid, AuthTableFile))
	if err != nil {
		return nil, err
	}
	var authTable AuthTable
	if err := json.Unmarshal(records, &authTable); err != nil {
		return nil, err
	}
	return authTable, nil
}

func GetAuthToken(uid string, vmid string) (string, error) {
	authTableMutex.Lock()
	defer authTableMutex.Unlock()

	authTable, err := getUserAuthTable(uid)
	if err != nil {
		return "", fmt.Errorf("failed to get auth token: %v", err)
	}
	token, ok := authTable[vmid]
	if !ok {
		return "", fmt.Errorf("no matching token found for %s", vmid)
	}
	return token, nil
}

func UpdateAuthToken(uid string, t AuthTable) error {
	authTableMutex.Lock()
	defer authTableMutex.Unlock()

	wholeTable, err := getUserAuthTable(uid)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to retrive whole auth data: %v", err)
		}
		wholeTable = AuthTable{}
	}
	for k, v := range t {
		wholeTable[k] = v
	}
	authData, err := json.Marshal(wholeTable)
	if err != nil {
		return fmt.Errorf("failed to marshal auth data: %v\n", err)
	}
	if err := os.WriteFile(filepath.Join(UserRuntimeDir, uid, AuthTableFile),
		authData, 0600); err != nil {
		return fmt.Errorf("failed to write back auth data: %v\n", err)
	}
	return nil
}

func RemoveAuthToken(uid string, vmid string) error {
	authTableMutex.Lock()
	defer authTableMutex.Unlock()

	wholeTable, err := getUserAuthTable(uid)
	if err != nil {
		return fmt.Errorf("failed to retrive whole auth data: %v", err)
	}
	delete(wholeTable, vmid)
	authData, err := json.Marshal(wholeTable)
	if err != nil {
		return fmt.Errorf("failed to marshal auth data: %v\n", err)
	}
	if err := os.WriteFile(filepath.Join(UserRuntimeDir, uid, AuthTableFile),
		authData, 0600); err != nil {
		return fmt.Errorf("failed to write back auth data: %v\n", err)
	}
	return nil
}

func IsLoggedIn(uid string, vmid string) (string, bool) {
	token, err := GetAuthToken(uid, vmid)
	if err != nil {
		return "", false
	}
	return token, true
}
