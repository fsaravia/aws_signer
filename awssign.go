package awssign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	algorithm         string = "AWS4-HMAC-SHA256"
	dateHeader        string = "X-Amz-Date"
	dateFormat        string = "20060102"
	dateTimeFormat    string = "20060102T150405Z"
	hostHeader        string = "host"
	terminationString string = "aws4_request"
)

type Signer struct {
	Region          string
	Service         string
	AccessKeyID     string
	AccessKeySecret string
}

func (signer *Signer) Sign(request *http.Request, payload string) {
	timestamp := time.Now().UTC()

	request.Header.Add(dateHeader, timestamp.Format(time.RFC3339))

	signedHeaders := signedHeaders(request.Header)
	credential := fmt.Sprintf("%s/%s", signer.AccessKeyID, credentialScope(timestamp, signer.Region, signer.Service))
	signature := AWSSignature(request, payload, timestamp, signer.Region, signer.Service, signer.AccessKeySecret)

	request.Header.Add("Authorization", fmt.Sprintf("%s, Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credential, signedHeaders, signature))
}

func AWSSignature(request *http.Request, payload string, timestamp time.Time, region, service, key string) string {
	string := canonicalString(request, payload)
	hashed := fmt.Sprintf("%x", sha256.Sum256([]byte(string)))
	stringToSign := stringToSign(timestamp, region, service, hashed)
	signingKey := deriveSigningKey(key, timestamp, region, service)

	return calculateSignature(signingKey, stringToSign)
}

func calculateSignature(signingKey []byte, stringToSign string) string {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(stringToSign))

	return hex.EncodeToString(mac.Sum(nil))
}

func deriveSigningKey(awsKey string, date time.Time, region, service string) []byte {
	sha := sha256.New

	kSecret := []byte("AWS4" + awsKey)

	mac := hmac.New(sha, kSecret)
	mac.Write([]byte(date.Format(dateFormat)))
	kDate := mac.Sum(nil)

	mac = hmac.New(sha, kDate)
	mac.Write([]byte(region))
	kRegion := mac.Sum(nil)

	mac = hmac.New(sha, kRegion)
	mac.Write([]byte(service))
	kService := mac.Sum(nil)

	mac = hmac.New(sha, kService)
	mac.Write([]byte(terminationString))

	return mac.Sum(nil)
}

func stringToSign(timestamp time.Time, region, service, hashedCanonicalRequest string) string {
	var buffer bytes.Buffer

	buffer.WriteString(algorithm)
	buffer.WriteString("\n")
	buffer.WriteString(timestamp.Format(dateTimeFormat))
	buffer.WriteString("\n")
	buffer.WriteString(credentialScope(timestamp, region, service))
	buffer.WriteString("\n")
	buffer.WriteString(hashedCanonicalRequest)
	return buffer.String()
}

func credentialScope(timestamp time.Time, region, service string) string {
	return fmt.Sprintf("%s/%s/%s/%s",
		timestamp.Format(dateFormat),
		region,
		service,
		terminationString)
}

func canonicalString(request *http.Request, payload string) string {
	var buffer bytes.Buffer

	buffer.WriteString(request.Method)
	buffer.WriteString("\n")
	buffer.WriteString(request.URL.EscapedPath())
	buffer.WriteString("\n")
	buffer.WriteString(request.URL.Query().Encode())
	buffer.WriteString("\n")
	buffer.WriteString(canonicalHeaders(request.Header, request.Host))
	buffer.WriteString("\n")
	buffer.WriteString(hashedBody(payload))

	return buffer.String()
}

func hashedBody(payload string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
}

func signedHeaders(header http.Header) string {
	var headerNames []string

	for name := range header {
		headerNames = append(headerNames, strings.ToLower(name))
	}
	headerNames = append(headerNames, hostHeader)

	sort.Strings(headerNames)

	return strings.Join(headerNames, ";")
}

func canonicalHeaders(header http.Header, host string) string {
	signedHeaders := signedHeaders(header)
	lowerCaseHeaders := make(map[string]string)

	for name, value := range header {
		lowerName := strings.ToLower(name)

		lowerCaseHeaders[lowerName] = strings.Join(value, " ")
	}
	lowerCaseHeaders[hostHeader] = host

	headerNames := strings.Split(signedHeaders, ";")

	var buffer bytes.Buffer

	for _, name := range headerNames {
		buffer.WriteString(name)
		buffer.WriteString(":")
		buffer.WriteString(lowerCaseHeaders[name])
		buffer.WriteString("\n")
	}

	buffer.WriteString("\n")
	buffer.WriteString(signedHeaders)

	return buffer.String()
}
