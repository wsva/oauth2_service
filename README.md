OAuth2Service provides OAuth2 services

# generate Ed25519 key
`````
openssl genpkey -algorithm Ed25519 -out ed25519.key
openssl pkey -in ed25519.key -pubout -out ed25519.pub
`````