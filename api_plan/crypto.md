#BOT COMMUNICATION PROTOCOL PROPOSAL

##HTTP REST API && DISCORD-BASED PUBLIC KEY AUTHENTICATION

##PART 1 - PUBLIC KEY AUTHENTICATION
An external bot attempting to communicate using authentication-requiring endpoints shall generate an ECDSA kpublic-private key pair for itself, whose expiration must be at most one month after its creation.
An external bot shall, upon request, use a discord command to submit their own ECDSA public key to the currency bot's key database. Said key will remain in the databse until it's expiration, at which point it will be deleted, and the bot should request a new key be added to the database before it is allowed to communicate any further.

For communication with the HTTP REST API the bot shall send a message to the endpoint as usual, but for any command requiring authorization, the parameters will contain an 'id' field, an account identifier, and a 'signature', containing a hexadecimal ECDSA signature of the rest of the request. Any authenticatable HTTP request will then look like:

```
POST:
parameterfield=value&\
parameterfield2=value&\
...
id=<identifier>&\
signature=<signature>
```

GET-requests will not require authentication, as encryption will be provided by HTTPS.
Pseudocode for creating such a url encoded material:

```
request = ""
for field in fields:
    request += field
    request += "="
    request += fields[field]
    request += "&"
request += "id="
request += id
request += "&signature="
request += sign(request)
```

A basic python implementation of the request protocol can be found in cryptoproof.py

##PART 2 - HTTP REST API

An external bot attempting to communicate with or without authentication will send a HTTP request to one of this bot's HTTP REST endpoints

Each command shall have it's own HTTP REST endpoint, and each HTTP REST endpoint shall be either GET or POST depending on whether it's public or requires authorization respectively.

HTTP REST endpoints will be called `/api/<command name>`
Examples of good HTTP REST endpoints:

```
GET /api/balance
POST /api/transfer
POST /api/add_account
POST /api/transfer
```

Each HTTP REST endpoint should have *clearly* named parameters

```
GET /api/balance
    Paremeters:
        account: Account identifier of the account whose balance is being requested

POST /api/transfer
    Parameters:
        from: Account identifier of the account to transfer from
        to: Account identifier of the account to transfer to
        amount: amount of currency to be transferred
        id: Account identifier of the account requesting the transfer (universal for all POST requests)
        signature: ECDSA signature of the account requesting the transfer (universal for all POST requests)
```

Each HTTP REST endpoint should output a status code based on handling of the request:

```
200 - Request accepted and operation completed successfully. Data returned is the data requested, if nothing was requested, return nothing
400 - Request unacceptable due to client error (e.g. insufficient/malformed parameters, not enough money). Data returned can be a human-readable error line, or nothing.
403 - Request unacceptable due to invalid signature. Data returned is nothing. Only for POST endpoints
404 - No such endpoint.
405 - Request unacceptable due to the wrong method being used.
500 - Server error while handling request. Data returned can be a human-readable error line, but as the client cannot do anything about this happening, best to return nothing.
```

##PART 3 - ENCRYPTION OF COMMUNICATIONS

Encryption shall be done through HTTPS using a "reverse proxy", such as `nginx`. This reverse proxy is to be configured to act as a sort of "encryption tunnel" through which the server and the foreign bot will communicate. Requests meant to the server will be sent encrypted to the reverse proxy, which decrypts them and passes them on to the server as unencrypted HTTP traffic.

```
[Client] ----HTTPS TRAFFIC---- [Reverse proxy] ----HTTP TRAFFIC--- [Server]
```

2020-05-08 
