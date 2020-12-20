package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

const (
	defaultConfigFilePath = "./config/config.json"
	SIGNING_ALGO = "AWS4-HMAC-SHA256"
	TERMINATION_STRING = "aws4_request"
	METHOD = "GET"
)

var errorLogger = log.New(os.Stderr, "ERROR ", log.Llongfile)

type SignatureResponse struct {
	Signature     float64 `json:"signature"`
}

type Configuration struct {
	AccessKey   string `json:"accessKey"`
	SecretKey 	string `json:"secretKey"`
}

func signerRequest(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	cfg, err := getConfig()
	if err != nil {
		log.Fatalf("Error getting config: %s", err)
	}

	if err != nil {
		errorLogger.Printf("failed creating session: %s", err)
		return serverError(err)
	}

	hostToSign := req.QueryStringParameters["host"]
	if hostToSign == "" {
		err := fmt.Errorf("no host provided in request")
		errorLogger.Printf("%s", err)
		return clientError(http.StatusBadRequest, err)
	}
	regionToSign := req.QueryStringParameters["region"]
	if regionToSign == "" {
		err := fmt.Errorf("no region provided in request")
		errorLogger.Printf("%s", err)
		return clientError(http.StatusBadRequest, err)
	}
	serviceToSign := req.QueryStringParameters["service"]
	if serviceToSign == "" {
		err := fmt.Errorf("no service provided in request")
		errorLogger.Printf("%s", err)
		return clientError(http.StatusBadRequest, err)
	}
	pathToSign := req.QueryStringParameters["path"]
	if pathToSign == "" {
		err := fmt.Errorf("no path provided in request")
		errorLogger.Printf("%s", err)
		return clientError(http.StatusBadRequest, err)
	}
	paramsToSign := req.QueryStringParameters["params"]
	if paramsToSign == "" {
		err := fmt.Errorf("no params provided in request")
		errorLogger.Printf("%s", err)
		return clientError(http.StatusBadRequest, err)
	}
	accessTokenToSign := req.QueryStringParameters["accessToken"]
	if accessTokenToSign == "" {
		err := fmt.Errorf("no accessToken provided in request")
		errorLogger.Printf("%s", err)
		return clientError(http.StatusBadRequest, err)
	}
	userAgentToSign := req.QueryStringParameters["userAgent"]
	if userAgentToSign == "" {
		err := fmt.Errorf("no userAgent provided in request")
		errorLogger.Printf("%s", err)
		return clientError(http.StatusBadRequest, err)
	}

	authorizationHeader := processSignature(*cfg, hostToSign, regionToSign, serviceToSign, pathToSign, paramsToSign, accessTokenToSign, userAgentToSign)

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       authorizationHeader,
	}, nil
}

func processSignature(cfg Configuration, hostToSign, regionToSign, serviceToSign, pathToSign, paramsToSign, accessTokenToSign, userAgentToSign string) string {

	currentTime := time.Now()
	dateStamp := fmt.Sprintf(currentTime.Format("20060102"))
	amzdate := fmt.Sprintf(currentTime.Format("20060102T150405Z"))

	canonicalHeaders := fmt.Sprintf("host:%s\nuser-agent:%s\nx-amz-access-token:%s\nx-amz-date:%s\n", hostToSign, userAgentToSign, accessTokenToSign, amzdate)
	signedHeaders := "host;user-agent;x-amz-access-token;x-amz-date"

	hasherPayload := sha256.New()
	hasherPayload.Write([]byte(""))
	payloadHash := hex.EncodeToString(hasherPayload.Sum(nil))
	canonicalReq := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", METHOD, pathToSign, paramsToSign, canonicalHeaders, signedHeaders, payloadHash)
	credScope := fmt.Sprintf("%s/%s/%s/%s", dateStamp, regionToSign, serviceToSign, TERMINATION_STRING)

	hasherCanonicalReq := sha256.New()
	hasherCanonicalReq.Write([]byte(canonicalReq))
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", SIGNING_ALGO, amzdate, credScope, hex.EncodeToString(hasherCanonicalReq.Sum(nil)))

	signingKey := getSignatureKey(cfg.SecretKey, dateStamp, regionToSign, serviceToSign)
	signature := hmac.New(sha256.New, []byte(signingKey))
	signature.Write([]byte(stringToSign))

	authorizationHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", SIGNING_ALGO, cfg.AccessKey, credScope, signedHeaders, hex.EncodeToString(signature.Sum(nil)))

	log.Printf("Signature is: %s", authorizationHeader)

	return authorizationHeader
}

func getSignatureKey(key, dateStamp, region, service string) string {
	kDate := sign(fmt.Sprintf("AWS4%s", key), dateStamp)
	kRegion := sign(kDate, region)
	kService := sign(kRegion, service)
	kSigning := sign(kService, TERMINATION_STRING)

	return kSigning
}

func sign (key, msg string) string {
	thisHash := hmac.New(sha256.New, []byte(key))
	thisHash.Write([]byte(msg))

	//return hex.EncodeToString(thisHash.Sum(nil))
	return string(thisHash.Sum(nil))
}

func getConfig() (*Configuration, error) {
	data, err := ioutil.ReadFile(defaultConfigFilePath)
	if err != nil {
		return nil, err
	}

	var cfg Configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	fmt.Printf("Using access key: %s\n", cfg.AccessKey)
	return &cfg, nil
}

func serverError(err error) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       fmt.Sprintf("%s - %s", http.StatusText(http.StatusInternalServerError), err.Error()),
	}, nil
}

func clientError(status int, err error) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       fmt.Sprintf("%s - %s", http.StatusText(status), err.Error()),
	}, nil
}

func main() {

	lambda.Start(signerRequest)
}
