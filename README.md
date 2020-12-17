# go-aws-v4-signer

## Usage
The service requires 5 parameters:
- host
- region
- service
- path
- params

It also takes the ACCESS_KEY and SECRET_KEY as configuration parameters in `config/config.json`.
```
{
  "accessKey": "",
  "secretKey": ""
}
```

To make a request:
```
curl -X GET "https://blahblah.execute-api.eu-west-1.amazonaws.com/default/v4signer?host=localhost&region=eu-west-1&service=execute-api&path=vendor/orders/v1/purchaseOrders&params=?limit={example}&createdAfter={example}&createdBefore={example}&sortOrder={example}&nextToken={example}&includeDetails={example}"
```
which returns:
```
AWS4-HMAC-SHA256 Credential=/20201217/eu-west-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=e2e86c0f98cd5aefdadf54f902d359e8a04b76ecaed2204e7b66970d4ef5660a
```
