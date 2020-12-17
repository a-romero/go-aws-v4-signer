package main

import (
	//"encoding/json"
	//"fmt"
	"log"
	//"net/http"
	"testing"

	//"github.com/stretchr/testify/assert"

	//"github.com/aws/aws-lambda-go/events"
	//"github.com/stretchr/testify/mock"
)

func TestProcessSignature(t *testing.T) {

	testCfg := Configuration{
		AccessKey: "AKIXXXXXXXXXXXXXX",
		SecretKey: "YJTRfg7s6adshji67sdhbkgabsd",
	}

	testHostToSign := "localhost"
	testRegionToSign := "eu-west-1"
	testServiceToSign := "execute-api"
	testPathToSign := "vendor/orders/v1/purchaseOrders"
	testParamsToSign := "?limit={example}&createdAfter={example}&createdBefore={example}&sortOrder={example}&nextToken={example}&includeDetails={example}"

	testAuthHeaders := processSignature(testCfg, testHostToSign, testRegionToSign, testServiceToSign, testPathToSign, testParamsToSign)

	log.Printf("Signature is: %s", testAuthHeaders)
}
