# Payshield-rest-api

This is a simple RestAPI for Thales payShield HSM. It has been tested with Thales payShield 9000 and payShield 10K. This example demonstrate how to check version of HSM, verify PIN, encrypt data and decrypt data using RestAPI.

## Installation

You need to install Gin framework to running this code. To install Gin package, you need to install Go and set your Go workspace first, then you can use the below Go command to install Gin:
```
> go get -u github.com/gin-gonic/gin
```

For server key and certificate, you can generate using application such as openssl. The command are below:
```
> openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```

## Usage

To run this code (server side), go to bin directory and execute:
```
> go run main.go
```
Or build the main file, then execute the executable file using command:
```
> go build main.go
> main.exe
```

You can use curl application or another GUI apps such as Postman as a client to connect to RestAPI server. You can use the files contained in the client folder as message data for the Rest API test.

### Check Version
```
> curl -k -X POST https://localhost:8080/version
{"firmwareNumber":"XXXX-XXXX","lmkCheck":"XXXXXXXXXXXXXXXX"}
```

### Verify PIN
```
> curl -k -X POST https://localhost:8080/verifypin --data-binary @verifypin.txt
{"errorCode":"true"}
```

### Encrypt Data
```
> curl -k -X POST https://localhost:8080/encrypt --data-binary @cleartext.txt
{"ciphertext":"7ibaZ4PV0M937lTsupfhDQ=="}
```

### Decrypt Data
```
> curl -k -X POST https://localhost:8080/decrypt --data-binary @ciphertext.txt
{"cleartext":"aGVsbG8gd29ybGQhISEAAA=="}
```

### Tokenise Data
```
> curl -k -X POST https://localhost:8080/tokenise -u "foo:bar" --data-binary @tokenise-profile1.txt
{"token":"6288248669598239"}

> curl -k -X POST https://localhost:8080/tokenise -u "johndoe:123456" --data-binary @tokenise-profile2.txt
{"token":"9453678359348564"}

> curl -k -X POST https://localhost:8080/tokenise -u "foo:bar" --data-binary @tokenise-profile2.txt
{"error":"Unauthorized"}
```

### Detokenise Data
```
> curl -k -X POST https://localhost:8080/detokenise -u "foo:bar" --data-binary @detokenise-profile1.txt
{"data":"9453677629008564"}

> curl -k -X POST https://localhost:8080/detokenise -u "johndoe:123456" --data-binary @detokenise-profile2.txt
{"data":"945367******8564"}

> curl -k -X POST https://localhost:8080/detokenise -u "custservice:p@ssw0rd" --data-binary @detokenise-profile3.txt
{"data":"############8564"}

> curl -k -X POST https://localhost:8080/detokenise -u "custservice:p@ssw0rd" --data-binary @detokenise-profile2.txt
{"error":"Unauthorized"}
```
