import os
from typing import Dict


class WalletConfig:
    """Runtime wallet configuration. Wallets are generated at runtime and stored only inside the container."""

    def __init__(self):
        self.wallet_store_path = os.getenv("WALLET_STORE_PATH", "/tmp/wallets.json")
        self.wallet_seeds: Dict[str, str] = {}

    def add_wallet(self, address: str, seed: str):
        self.wallet_seeds[address] = seed

    def get_seed(self, address: str):
        return self.wallet_seeds.get(address)


wallet_config = WalletConfig()