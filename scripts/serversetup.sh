mkdir .keys/ .keys/jwt .db/;
openssl genpkey -algorithm Ed25519 -out .keys/jwt/privateKey.pem;
openssl pkey -in .keys/jwt/privateKey.pem -pubout -out .keys/jwt/publicKey.pem;
openssl ecparam -out .keys/privateKey.pem -name secp521r1 -genkey;
openssl req -new -key .keys/privateKey.pem -x509 -nodes -days 700 -out .keys/certificate.crt;
