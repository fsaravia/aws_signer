package AWSSigner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const (
	region  string = "us-east-1"
	service string = "iam"
)

func fakeRequest() *http.Request {
	query := url.Values{}
	query.Add("Action", "ListUsers")
	query.Add("Version", "2010-05-08")

	parsedUrl, _ := url.Parse("https://iam.amazonaws.com/")
	parsedUrl.RawQuery = query.Encode()

	request, _ := http.NewRequest(http.MethodGet, parsedUrl.String(), nil)

	request.Header.Add("X-Amz-Date", "20150830T123600Z")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	return request
}

func TestCanonicalString(t *testing.T) {
	expected := `GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
	got := canonicalString(fakeRequest())

	if got != expected {
		t.Errorf("Expected: %s\nGot: %s", expected, got)
	}
}

func TestStringToSign(t *testing.T) {
	canonicalString := canonicalString(fakeRequest())
	hashedCanonicalString := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalString)))

	expected := `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`

	time := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

	got := stringToSign(time, region, service, hashedCanonicalString)

	if got != expected {
		t.Errorf("Expected: %s\nGot: %s", expected, got)
	}
}

func TestDeriveSigningKey(t *testing.T) {
	awsKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	time := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

	expected := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"

	// translate the encoding to a comparable format for testing purposes
	got := hex.EncodeToString(deriveSigningKey(awsKey, time, region, service))

	if got != expected {
		t.Errorf("Expected: %s\nGot: %s", expected, got)
	}
}

func TestCalculateSignature(t *testing.T) {
	stringToSign := `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`

	awsKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	time := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

	// translate the encoding to a comparable format
	signignKey := deriveSigningKey(awsKey, time, region, service)

	expected := "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"

	got := calculateSignature(signignKey, stringToSign)

	if got != expected {
		t.Errorf("Expected: %s\nGot: %s", expected, got)
	}
}

func TestAWSSignature(t *testing.T) {
	awsKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	timestamp := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	request := fakeRequest()
	expected := "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	got := AWSSignature(request, timestamp, region, service, awsKey)

	if got != expected {
		t.Errorf("Expected: %s\nGot: %s", expected, got)
	}
}
