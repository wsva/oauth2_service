OAuth2Service provides OAuth2 services

# generate RSA key
`````
openssl genrsa -out rsa.key 3072
openssl rsa -in rsa.key -pubout -out rsa.pub
`````

# generate Ed25519 key
`````
openssl genpkey -algorithm Ed25519 -out ed25519.key
openssl pkey -in ed25519.key -pubout -out ed25519.pub
`````

Auth.js doesn't support Ed25519.