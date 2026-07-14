from xrpl.clients import JsonRpcClient
from xrpl.asyncio.clients import AsyncJsonRpcClient
from xrpl.wallet import Wallet
from xrpl.asyncio.wallet import generate_faucet_wallet as async_generate_faucet_wallet
from xrpl.models.transactions import Payment, Memo
from xrpl.models.requests import Tx, AccountInfo
from xrpl.transaction import autofill_and_sign
from xrpl.utils import xrp_to_drops
from xrpl.asyncio.transaction.reliable_submission import submit_and_wait
from xrpl.asyncio.transaction import autofill_and_sign
from app.settings import settings

# Async initialize XRPL client for funding DevNet
_asyncClient = AsyncJsonRpcClient(settings.xrpl_rpc_url)

def get_asyncClient() -> AsyncJsonRpcClient:
    return _asyncClient

async def get_devnet_wallet_async() -> Wallet:
    # Generate and fund a wallet on DevNet, returning an instance with address, seed, public & private keys.
    wallet = await async_generate_faucet_wallet(get_asyncClient(), debug=True)
    return wallet

def wallet_from_seed(seed: str) -> Wallet:
    # Restore a wallet from seed. This will derive both public and private keys.
    return Wallet.from_seed(seed)  # public_key, private_key and address included


async def get_account_balance_xrp(address: str) -> float:
    # Returns the current account balance in XRP.
    client = get_asyncClient()
    response = await client.request(AccountInfo(account=address, ledger_index="validated"))
    if "account_data" not in response.result:
        return 0.0
    balance_drops = int(response.result["account_data"]["Balance"])
    return float(balance_drops) / 1_000_000  # drops → XRP

async def anchor_hash(wallet: Wallet, hash_hex: str, destination: str) -> tuple[str, int | None]:
    txn = Payment(
        account=wallet.address,
        destination=destination,
        # sending 10 drops (a mil XRP)
        amount=xrp_to_drops(0.00001),
        # sending the hash of the file as a memo on the transaction
        memos=[Memo(memo_data=hash_hex)],
    )
     # Sign, autofill, submit, and wait for validation
     # Autofill missing fields including sequence and last_ledger_sequence, then sign
    signed_txn = await autofill_and_sign(txn, get_asyncClient(), wallet)
    response = await submit_and_wait(signed_txn, get_asyncClient(), wallet)
    result = response.result
    tx_hash = result.get("hash") or result.get("tx_json", {}).get("hash")
    ledger_index = result.get("ledger_index")
    print("Transaction", tx_hash, "was validated in ledger:", ledger_index)
    if not tx_hash:
        raise ValueError("Transaction hash not found in response.")
    # Now the transaction is validated; return the hash and ledger index
    return tx_hash, ledger_index


async def fetch_transaction(tx_hash: str) -> dict:
    client = get_asyncClient()
    response = await client.request(Tx(transaction=tx_hash,binary=False))
    return response.result.get("tx_json", {})