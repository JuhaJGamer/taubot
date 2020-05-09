from aiohttp import web
import inspect
import base64
from typing import Union
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

async def handle_signed_request(request, account, server):
    signature = bytes.fromhex((await request.post())['signature'])
    crypto_text = "&".join([ f for f in (await request.text()).split("&") if f[:9] != "signature" ]) + "&"
    h = SHA256.new(crypto_text.encode('utf-8'))
    for key in account.list_public_keys():
        verifier = DSS.new(key,'fips-186-3')
        try:
            verifier.verify(h,signature)
            return True
        except ValueError:
            pass
    return False

def check_acc_name(account_name: Union[str, accounting.AccountId]) -> accounting.AccountId:
    if isinstance(account_name, str):
        return accounting.parse_account_id(account_name)
    else:
        return account_name

def web_assert_is_account(account_name: Union[str, accounting.AccountId], server: accounting.Server) -> accounting.Account:
    account_name = check_acc_name(account_name)
    if not server.has_account(account_name):
        raise web.HTTPBadRequest(body=f'No such account: {account_name}')
    else:
        return server.get_account(account_name)

def web_assert_authorized(account_name: Union[str, accounting.AccountId], server: accounting.Server, auth_level: accounting.Authorization) -> accounting.Account:
    account = web_assert_is_account(account_name,server)
    if account.get_authorization().value < auth_level.value:
        raise web.HTTPForbidden(body='Unauthorized command')
    else:
        return account

class RestEndpoint:

    def __init__(self, server : accounting.Server):
        self.methods = {}
        self.server = server

        for method_name in ('POST', 'GET', 'PUT', 'DELETE'):
            method = getattr(self, method_name.lower(), None)
            if method:
                self.register_method(method_name, method)

    def register_method(self, method_name, method):
        self.methods[method_name.upper()] = method

    async def dispatch(self, request: web.Request):
        method = self.methods.get(request.method.upper())
        if not method:
            raise web.HTTPMethodNotAllowed('', ('POST''GET','PUT','DELETE'))

        wanted_args = list(inspect.signature(method).parameters.keys())
        available_args = request.query.copy()
        available_args.update(await request.post())
        available_args.update({'request':request})

        if request.method.upper() == "POST":
            try:
                acc = web_assert_is_account(available_args['id'], self.server)
                if await handle_signed_request(request,acc,self.server):
                    available_args.update({'caller':available_args['id']})
                else:
                    raise web.HTTPForbidden(body='Bad signature')
            except KeyError:
                raise web.HTTPBadRequest(body='"id" and "signature" fields required for POST endpoints.')

        unsatisfied_args = set(wanted_args) - set(available_args.keys())
        if unsatisfied_args:
            raise web.HTTPBadRequest(body='Unsatisfied parameters')

        return await method(**{arg_name: available_args[arg_name] for arg_name in wanted_args})

class BalanceEndpoint(RestEndpoint):

    async def post(self, request,caller,account) -> web.Response:
        account_id = accounting.parse_account_id(account)
        if not self.server.has_account(account_id):
            raise web.HTTPBadRequest(body='No such account')
        if caller != account:
            web_assert_authorized(caller,server,accounting.Authorization.ADMIN)

        return web.Response(text=json.dumps({
            'account':caller,
            'value':self.server.get_account(account_id).get_balance()
            }))

class AddPubKeyEndpoint(RestEndpoint):

    async def get(self, account, pubkey) -> web.Response:
        account = web_assert_is_account(account, self.server)
        try:
            key = base64.decodebytes(bytes.fromhex(pubkey)).decode('utf-8')
            key = ECC.import_key(key)
        except Exception as e:
            raise web.HTTPBadRequest(body='"pubkey" parameter should be hex encoded utf-8 encoded base64 of a pem file containing an ECDSA public key')
        self.server.add_public_key(account,key)
        return web.Response(text='')

class AddAccountEndpoint(RestEndpoint):

    async def get(self, account) -> web.Response:
       account = check_acc_name(account)
       self.server.open_account(account)
       return web.Response(text='')

class RestApi:
    def __init__(self, prefix, router, server):
        self.router = router
        self.prefix = prefix

        self.add_route('balance', BalanceEndpoint(server))
        self.add_route('addpubkey',AddPubKeyEndpoint(server))
        self.add_route('openaccount',AddAccountEndpoint(server))

    def add_route(self, path:str, endp : RestEndpoint):
        self.router.add_route('*',self.prefix + path,endp.dispatch)





