package service

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	UserRuntimeDir = "/run/user"
	AuthTableFile  = "tokens.json"
)

// map vmid to associated access token
type AuthTable map[string]string

func getUserAuthTable(f *os.File) (AuthTable, error) {
	finfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	records := make([]byte, finfo.Size())
	n, err := f.Read(records)
	if err != nil {
		return nil, err
	}
	var authTable AuthTable
	if err := json.Unmarshal(records[:n], &authTable); err != nil {
		return nil, err
	}
	return authTable, nil
}

func GetAuthToken(uid string, vmid string) (string, error) {
	f, err := os.Open(filepath.Join(UserRuntimeDir, uid, AuthTableFile))
	if err != nil {
		return "", fmt.Errorf("failed to open auth file: %v", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return "", err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	authTable, err := getUserAuthTable(f)
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
	filename := filepath.Join(UserRuntimeDir, uid, AuthTableFile)
	f, err := os.OpenFile(filename, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open auth file: %v", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	wholeTable, err := getUserAuthTable(f)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to retrive whole auth data: %v", err)
		}
		wholeTable = AuthTable{}
	} else {
		current := time.Now().UTC().Unix()
		for vmid, sk := range wholeTable {
			expired, err := isExpired(sk, current)
			if err != nil {
				return fmt.Errorf("failed to determine expiration: %v", err)
			}
			if expired {
				delete(wholeTable, vmid)
			}
		}

	}
	for k, v := range t {
		wholeTable[k] = v
	}
	authData, err := json.Marshal(wholeTable)
	if err != nil {
		return fmt.Errorf("failed to marshal auth data: %v\n", err)
	}

	f.Truncate(0)
	if _, err := f.Write(authData); err != nil {
		return fmt.Errorf("failed to write back auth data: %v\n", err)
	}
	return nil
}

func RemoveAuthToken(uid string, vmid string) error {
	filename := filepath.Join(UserRuntimeDir, uid, AuthTableFile)
	f, err := os.OpenFile(filename, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open auth file: %v", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	wholeTable, err := getUserAuthTable(f)
	if err != nil {
		return fmt.Errorf("failed to retrive whole auth data: %v", err)
	}
	delete(wholeTable, vmid)

	current := time.Now().UTC().Unix()
	for vmid, sk := range wholeTable {
		expired, err := isExpired(sk, current)
		if err != nil {
			return fmt.Errorf("failed to determine expiration: %v", err)
		}
		if expired {
			delete(wholeTable, vmid)
		}
	}

	authData, err := json.Marshal(wholeTable)
	if err != nil {
		return fmt.Errorf("failed to marshal auth data: %v\n", err)
	}

	f.Truncate(0)
	if _, err := f.Write(authData); err != nil {
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

func getExpirationFromSessionKey(sk string) (int64, error) {
	b := []byte(sk)
	var duration int64
	buf := bytes.NewReader(b[:8])
	if err := binary.Read(buf, binary.LittleEndian, &duration); err != nil {
		return 0, err
	}
	return duration, nil
}

func isExpired(sk string, current int64) (bool, error) {
	expiration, err := getExpirationFromSessionKey(sk)
	if err != nil {
		return true, err
	}
	return current >= expiration, nil
}
