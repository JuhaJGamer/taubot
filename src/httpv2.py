from aiohttp import web
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import json
import accounting, commands

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

def handle_signed_request(request, server):
    try:
        account = server.get_account(request.query['id'])
    except Exception as e:
        return False
    signature = request.query['signature']
    crypto_text = "&".join([ f for f in request.text.split("&") if f[:9] is not "signature" ]) + "&"
    h = SHA256.new(text.encode('utf-8'))
    for key in account.list_public_keys():
        verifier = DSS.new(key,'fips-186-3')
        try:
            verifier.verify(h,crypto_text)
            return True
        except ValueError:
            pass
    return False

def check_acc_name(account_name: Union[str, AccountId]) -> AccountId:
    if isinstance(account_name, str):
        return accounting.parse_account_id(account_name)
    else:
        return account_name

def web_assert_is_account(account_name: Union[str, AccountId], server: Server) -> Account:
    account_name = check_acc_name(account_name)
    if not server.has_account(account_name):
        raise web.HttpBadRequest(f'No such account: {account_name}')
    else:
        return self.server.get_account(account_name)

def web_assert_authorized(account_name: Union[str, AccountId], server: Server, auth_level: accounting.Authorization) -> Account:
    account = web_assert_is_account(account_name,server)
    if account.get_authorization().value < auth_level.value:
        raise web.HttpForbidden('Unauthorized command')
    else:
        return account

class RestEndpoint:

    def __init__(self, server : accounting.Server):
        self.methods = {}
        self.server = server

        for method_name in ('POST', 'GET', 'PUT', 'DELETE'):
            method = getattr(self, method.name.lower(), None)
            if method:
                self.register_method(method_name, method)

    def register_method(self, method_name, method):
        self.methods[method_name.upper()] = method

    async def dispatch(self, request: web.Request):
        method = self.methods.get(request.method.upper())
        if not method:
            raise web.HttpMethodNotAllowed('', ('POST''GET','PUT','DELETE')

        wanted_args = list(inspect.signature(method).parameters.keys())
        available_args = request.match_info.copy()
        available_args.update({'request':request})

        if request.method.lower() == "POST":
            try:
                if handle_signed_request(req,server):
                    available_args.update({'caller':self.server.get_account(request.query['id'])})
                else:
                    raise web.HTTPForbidden('Bad signature')
            except KeyError:
                raise web.HttpBadRequest('"id" and "signature" fields required for POST endpoints.')

        unsatisfied_args = set(wanted_args) - set(available_args.keys())
        if unsatisfied_args:
            raise web.HttpBadRequest('Unsatisfied parameters')

        return await method(**{arg_name: available_args[arg_name] for arg_name in wanted_args})

class BalanceEndpoint(RestEndpoint):

    async def post(self, request,caller,account) -> Response:
        account_id = accounting.parse_account_id(account)
        if self.server.has_account()):
            raise web.HttpBadRequest('No such account')
        if caller != account:
            web_assert_authorized(caller,server,accounting.Authorization.ADMIN)

        return web.Response(text=json.stringify({
            'account':caller,
            'value':self.server.get_account(account_id).get_balance()
            }))

class AddPubKeyEndpoint(RestEndpoint):

    async def get(self, account, pubkey):
        account = web_assert_is_account(account, self.server)
        try:
            key = base64.decodestring(bytes.fromhex(pubkey).decode('utf-8'))
            key = ECC.import_key(key)
        except Exception as e:
            raise web.HttpBadRequest('"pubkey" parameter should be hex encoded utf-8 encoded base64 of a pem file containing an ECDSA public key')
        server.add_public_key(account_key)
        return web.Response(text='')

class AddAccountEndpoint(RestEndpoint):

    async def get(self, account):
       account = check_acc_name(account)
       server.open_account(account)
       return web.Response(text='')

class RestApi:
    def __init__(self, prefix, router, server):
        self.router = router
        self.prefix = prefix

        self.add_route('balance', BalandeEndpoint(server))
        self.add_route('addpubkey',AddPubKeyEndpoint(server))
        self.add_route('openaccount',AddAccountEndpoint(server))

    def add_route(self, path:str, endp : RestEndpoint):
        self.router.add_route(self.prefix + path,endp.dispatch)





