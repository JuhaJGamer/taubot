from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

def sign_text(text,key):
    key = ECC.import_key(key)
    h = SHA256.new(text.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return signature

def verify_signature(text,signature,pkey):
    key = ECC.import_key(pkey)
    h = SHA256.new(text.encode('utf-8'))
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def create_signed_request(fields,id,key):
    req = ""
    for field in fields:
        req += f"{field}={fields[field]}&"
    req += f"id={id}&"
    req += f"signature={sign_text(req,key).hex()}"
    return req

def handle_signed_request(req, key_database):
    fields = {}
    for field in req.split("&"):
        temp = field.split("=")
        fields[temp[0]]=temp[1]

    if "signature" not in fields or "id" not in fields:
        raise ValueError("Expected both 'id' and 'signature' fields as part of request")

    verifiable_req = "&".join(req.split("&")[:-1]) + "&"
    if not verify_signature(verifiable_req, bytes.fromhex(fields["signature"]), key_database[fields["id"]]):
        return None
    else:
        return fields

if __name__ == "__main__":
    import json
    key = ECC.generate(curve='P-256')
    privkey = key.export_key(format='PEM')
    pubkey = key.public_key().export_key(format='PEM')
    account_id = "test_id/001"

    # Adding pubkey to server DB
    key_database = {account_id:pubkey}

    # Client side message generation
    msg = \
    {
        "command":"transfer",
        "from":"test_id/001",
        "to":"test_id/002",
        "value":"10"
    }
    req = create_signed_request(msg , account_id, privkey)

    # Server side request handling
    def handle_req(req):
        req_values = handle_signed_request(req, key_database)
        if req_values is None:
            print("Invalid request")
        else:
            print(f"Received request: {json.dumps(req_values, indent=2)}")
    print("Passing valid request")
    print(f"Sent request: {req}")
    handle_req(req)
    print("Passing invalid request")
    print(f"Sent request: {req[:-2] + '1a'}")
    handle_req(req[:-2] + "1a")





