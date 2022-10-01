package cbc3_test

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"strings"
	"testing"

	cbc3 "github.com/pschou/go-cbc3"
)

var SSH1unencrypted = b64decode(`
  U1NIIFBSSVZBVEUgS0VZIEZJTEUgRk9STUFUIDEuMQoAAAAAAAAAAAQABACyVhLTcHAKqu8YkxMR
  fuq2ZtvfBAZ/ZD+TT6+sjhLSTQ+YjO2twb3Ku8eYiTKFcT40mSaMhq0Ei9YG1iGyLdDJLUF4s4HO
  ua138J1SQJac1BDzWBy+PUqoeRk2TuvvwVFAUZ8ZlMz8suw7WvWWYnkqPVCCiHVDNLm9awpBP1y8
  lQAGJQAAABByc2Eta2V5LTIwMjIwOTE4u3i7eAP+MDLwVNJHy4gk8eKPiDAjwphXGa4PmA1BnW97
  lmuWYloENxFU/odjukCWz0esyh6bMM9yM9FfMalAw5PRwXQqlsg6xz/LY7tguSxtlBDxwluOnCcv
  7EereEdcSGTTB5iEZOcxRJrvMgIUQlHSzc9uDAnPslFOuADLrYeR7/uUhkUB/jGTA5jF6NDanWN2
  xyRCO1dumGfkhexTqGRA5WtUz/DxHZch1iD3Ek8dC0OF2jr7f8Ig3PbC4RfHyNd0pOZNTK4CALwe
  cv5UIIslQKzt3POQpi3P8YAaE7oed/Di6m/325lS6AB4bfWIaAQeywg9Nep/meiS1AuDslwBl/5s
  +JbXC5MCAPKv8Ukjifk78IWznkGHdFN+Jno3wEbLWeaUDNBNq0B64vm9LchpKHPo4VcsZvh7/WOj
  mraBgaKTVpCa6lJ5wDcAAAAA`)

var SSH1encrypted = b64decode(`
  U1NIIFBSSVZBVEUgS0VZIEZJTEUgRk9STUFUIDEuMQoAAwAAAAAAAAQABACyVhLTcHAKqu8YkxMR
  fuq2ZtvfBAZ/ZD+TT6+sjhLSTQ+YjO2twb3Ku8eYiTKFcT40mSaMhq0Ei9YG1iGyLdDJLUF4s4HO
  ua138J1SQJac1BDzWBy+PUqoeRk2TuvvwVFAUZ8ZlMz8suw7WvWWYnkqPVCCiHVDNLm9awpBP1y8
  lQAGJQAAABByc2Eta2V5LTIwMjIwOTE4jGWS/2YMLF+EayIjJtsJYvfV5ZRhfWwvW6uZm9I+6Qyq
  Jg2Rts81YB7iwlMBBEWxdHi+gOIx3p5RpP48QlXGXnv/8vv62yR/iadL802Rto6uIwN9WA8KGZ/a
  +pe64e8xa3sYX9622XCT4pA8lB3Mb9+AiBzra+GSH8wLlU6k9IZusvCwK+/ToBlFCrWAeKLKHNBK
  VuR2QjspFldSXj46AsUmTrFYgATQHCW8BkfMtZFYTFFi+ZkgrZMOM2hg0p4gVMNVw5YQLPdiyLjm
  SKxOEFB/z1YygVd5PKS9rF3fw2UeSSXq02hoGEotZwmRMa7QAN4hJ7N/8KlDB9M1768mcOY9TD2j
  Dv3NsaCgX0rD8+juS+L59QZyP9gOcOSIPq2o5etDcDKdZFPLDYKqAbKQK/As/5+1WRXfLy/XjTfN
  Psg/DuQZf57RNQ3+y9wy2yqK`)

func TestSSH1Encrypt(t *testing.T) {
	hash := md5.Sum([]byte("testit"))
	key := hash[:]
	b1, err := des.NewCipher(key[:8])
	if err != nil {
		t.Errorf("B1 error: %s", err)
	}
	b2, err := des.NewCipher(key[8:])
	if err != nil {
		t.Errorf("B2 error: %s", err)
	}
	b3, err := des.NewCipher(key[:8])
	if err != nil {
		t.Errorf("B3 error: %s", err)
	}

	unencrypted := SSH1unencrypted[195:]
	copy(unencrypted, []byte{111, 130, 111, 130})
	des3cbc3 := cbc3.NewEncrypter(b1, b2, b3, make([]byte, 24))
	new := make([]byte, len(unencrypted))
	des3cbc3.CryptBlocks(new, unencrypted)

	encrypted := SSH1encrypted[195:]
	if bytes.Compare(new[4:], encrypted[4:]) != 0 {
		t.Errorf("Failed to encrypt properly")
	}
}

func TestSSH1Decrypt(t *testing.T) {
	hash := md5.Sum([]byte("testit"))
	key := hash[:]
	b1, err := des.NewCipher(key[:8])
	if err != nil {
		t.Errorf("B1 error: %s", err)
	}
	b2, err := des.NewCipher(key[8:])
	if err != nil {
		t.Errorf("B2 error: %s", err)
	}
	b3, err := des.NewCipher(key[:8])
	if err != nil {
		t.Errorf("B3 error: %s", err)
	}

	encrypted := SSH1encrypted[195:]
	des3cbc3 := cbc3.NewDecrypter(b1, b2, b3, make([]byte, 24))
	new := make([]byte, len(encrypted))
	des3cbc3.CryptBlocks(new, encrypted)

	unencrypted := SSH1unencrypted[195:]
	if bytes.Compare(new[4:], unencrypted[4:]) != 0 {
		t.Errorf("Failed to decrypt properly")
	}
}

func b64decode(str string) []byte {
	noWhiteSpace := strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "")
	dat, _ := base64.StdEncoding.DecodeString(noWhiteSpace.Replace(str))
	return dat
}
