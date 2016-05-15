# Golang AWSSigner

[![Build Status](https://travis-ci.org/fsaravia/aws_signer.svg?branch=master)](https://travis-ci.org/fsaravia/aws_signer)

`AWSSigner` is a Go library for signing AWS requests according to the specifications of the [AWS Signature Version 4 Signing Process](http://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html).

# Why?

AWS provides a full featured [Go SDK](https://github.com/aws/aws-sdk-go) but this tiny library allows to sign just simple requests when you don't need to install the full SDK. Besides, Go is fun :wink:

# Install

```bash
$ go get github.com/fsaravia/aws_signer
```

# Usage

Create the HTTP request you'd like to sign.

```go
parsedUrl, _ := url.Parse("https://iam.amazonaws.com/")

query := url.Values{}
query.Add("Action", "ListUsers")
query.Add("Version", "2010-05-08")

parsedUrl.RawQuery = query.Encode()

request, _ := http.NewRequest(http.MethodGet, parsedUrl.String(), nil)

request.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
```

Instantiate a `Signer` and sign it!

```go
signer := AWSSigner.Signer{
	Region:          "us-east-1",
	Service:         "iam",
	AccessKeyID:     "<YOUR-ACCESS-KEY-ID>",
	AccessKeySecret: "<YOUR-ACCESS-KEY-SECRET>"}

signer.Sign(request, "")
```

If your request includes a body, pass its payload in the second parameter of `Sign`

```go
// Payload to send an email via SES

form := url.Values{}
form.Add("Action", "SendEmail")
form.Add("Destination.ToAddresses.member.1", "destination@example.org")
form.Add("Message.Body.Text.Data", "Test email body")
form.Add("Message.Subject.Data", "Test email subject")
form.Add("Source", "noreply@example.org")

payload := form.Encode()

request, _ := http.NewRequest(requestMethod, parsedUrl.String(), strings.NewReader(payload))

signer := AWSSigner.Signer{
	Region:          "us-east-1",
	Service:         "ses",
	AccessKeyID:     "<YOUR-ACCESS-KEY-ID>",
	AccessKeySecret: "<YOUR-ACCESS-KEY-SECRET>"}

signer.Sign(request, payload)
```
