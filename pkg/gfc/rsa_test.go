package gfc

import (
	"bytes"
	"os"
	"testing"
)

func TestRSA(t *testing.T) {
	pubFile := "./scripts/files/pub.pem"
	priFile := "./scripts/files/pri.pem"

	pubPEM, err := os.ReadFile(pubFile)
	if err != nil {
		t.Logf("failed to read public key file from %s", pubFile)
		t.SkipNow()
	}
	priPEM, err := os.ReadFile(priFile)
	if err != nil {
		t.Logf("failed to read public key file from %s", priFile)
		t.SkipNow()
	}

	plaintext := []byte("this_is_my_plain_text")
	ciphertext, err := EncryptRSA(bytes.NewBuffer(plaintext), pubPEM)
	if err != nil {
		t.Fatalf("error encrypting RSA: %s", err.Error())
	}
	plaintextBuf, err := DecryptRSA(ciphertext, priPEM)
	if err != nil {
		t.Fatalf("error decrypting RSA: %s", err.Error())
	}

	if !bytes.Equal(plaintextBuf.(*bytes.Buffer).Bytes(), plaintext) {
		t.Fatal("output does not match")
	}
}

func TestRSAPKIXKeys(t *testing.T) {
	plaintext := []byte("this_is_my_plain_text")
	pub := []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwZf9X2xOevb5mwXPwfPb
aK+QPJ7eWR6p6u/8jQDl15jxT6JVVErNq1X+9RYIn9dIcs07Zdr1hn7EEqI1wdyB
hQLUdRSZpgKteqgQhKGT6Xv0KrNukDsdzHdFFRbNTNDj7SOe5k3jXUAInoFBkU8m
cjnVvewJYcsdR88+QAdVonE2XB1KwGPjwL6YLmYznDT+3uB0KHJlWT44SL4DQQ3A
6CPqc5HsbVOF+ggdrEEySBQVbpSkxcVIv7uuFWVETtQFPPZkDA5NR8N7ORfSiLRv
JFdAEAij9w0nJkGoatLmVr/hOPWCxQ93rV97ojqsK9lI3n1AIKJOZZdfmuSin5XB
HZp9VMoxKFjIX3hKzTtT4YFD8uYo/AZvLFqkjagUh9gvrwDi21ntpbuAuW5h64r9
Obr5OTtlm03J4sXkxTKfN6sZyGgMXTTFY8Io11akly6qSbJOh8jmnuYTPflICnSz
1ULARZjShDWjq8S/cJXJ6P55+fENjxevKBc07+mzk1V37no/Hh7SeQkrVsMNyQmy
1AHTafRiQzyWl0q85B5JnOmBPy0xj2EO51mKyhZMQ+7jXzLyj1DbzxsDhKrnH7Pv
Htg3u1J4KTxsVuNC1lYBOnNa8d8gEuySS/p3tQgnbUVM+8DNUBu0rZ5Tugl4juTI
qns5IIvVeVCYgMfEE3o9xAUCAwEAAQ==
-----END PUBLIC KEY-----`)
	pri := []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
	ciphertext, err := EncryptRSA(bytes.NewBuffer(plaintext), pub)
	if err != nil {
		t.Fatalf("RSA encrypt with PKIX failed: %s", err.Error())
	}
	plaintextBuf, err := DecryptRSA(ciphertext, pri)
	if err != nil {
		t.Fatalf("RSA decrypt with PKIX failed: %s", err.Error())
	}
	decrypted := plaintextBuf.(*bytes.Buffer).Bytes()
	if !bytes.Equal(decrypted, plaintext) {
		t.Logf("plaintext: %s\ndecrypted: %s", plaintext, decrypted)
		t.Fatal("output does not match")
	}
}
