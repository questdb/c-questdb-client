# TLS Keys Creation

When creating self-signed X.509 certificates for testing, these need to v3.

Version 1 certificates will fail with error `UnsupportedCertVersion`.

The test certificates checked in here for testing were created with the
following steps.

## Create CA key and cert

`$ openssl genrsa -out server_rootCA.key 2048`
```
Generating RSA private key, 2048 bit long modulus
..........+++
........+++
e is 65537 (0x10001)
```

`$ openssl req -x509 -new -nodes -key server_rootCA.key -sha256 -days 3650 -out server_rootCA.pem`
```
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:GB
State or Province Name (full name) []:Greater London
Locality Name (eg, city) []:London
Organization Name (eg, company) []:QuestDB
Organizational Unit Name (eg, section) []:Testing
Common Name (eg, fully qualified host name) []:localhost
Email Address []:no-reply@questdb.io
```

## Create server_rootCA.csr.cnf

`$ vim server_rootCA.csr.cnf`
```
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C=GB
ST=Greater London
L=London
O=QuestDB
OU=Testing
emailAddress=no-reply@questdb.io
CN=localhost
```

## Create v3.ext configuration file

`$ vim v3.ext`
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
```

## Create server key

`$ openssl req -new -sha256 -nodes -out server.csr -newkey rsa:2048 -keyout server.key -config <( cat server_rootCA.csr.cnf )`
```
Generating a 2048 bit RSA private key
.................+++
.................................+++
writing new private key to 'server.key'
-----
```

## Create server cert

`$ openssl x509 -req -in server.csr -CA server_rootCA.pem -CAkey server_rootCA.key -CAcreateserial -out server.crt -days 3650 -sha256 -extfile v3.ext`
```
Signature ok
subject=/C=GB/ST=Greater London/L=London/O=QuestDB/OU=Testing/emailAddress=no-reply@questdb.io/CN=localhost
Getting CA Private Key
```

## Consolidated certs for haproxy

`$ cat server.crt server.key > server.pem`

## Reference

https://serverfault.com/questions/845766/generating-a-self-signed-cert-with-openssl-that-works-in-chrome-58

