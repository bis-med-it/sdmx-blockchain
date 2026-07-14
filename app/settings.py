import os


class Settings:
    def __init__(self):
        self.xrpl_rpc_url = os.getenv("XRPL_RPC_URL", "https://s.devnet.rippletest.net:51234/")
        self.xrpl_faucet_url = os.getenv("XRPL_FAUCET_URL", "https://faucet.devnet.rippletest.net/accounts")
        self.wallet_store_path = os.getenv("WALLET_STORE_PATH", "/tmp/wallets.json")
        self.attestation_store_path = os.getenv("ATTESTATION_STORE_PATH", "/tmp/attestations.json")
        self.bbs_key_store_path = os.getenv("BBS_KEY_STORE_PATH", "/tmp/bbs_keys.json")
        self.object_store_path = os.getenv("OBJECT_STORE_PATH", "/tmp/sdmx_objects")
        self.metadata_store_path = os.getenv("METADATA_STORE_PATH", "/tmp/anchor_metadata.json")
        self.backend_url = os.getenv("BACKEND_URL", "http://localhost:8000")
        self.keycloak_url = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
        self.keycloak_realm = os.getenv("KEYCLOAK_REALM", "sdmx")
        self.keycloak_client_id = os.getenv("KEYCLOAK_CLIENT_ID", "sdmx-client")
        self.keycloak_client_secret = self._read_file(
            os.getenv("KEYCLOAK_CLIENT_SECRET_FILE", "/tmp/secrets/KEYCLOAK_CLIENT_SECRET.txt")
        )
        self.postgres_user = os.getenv("POSTGRES_USER", "sdmxuser")
        self.postgres_db = os.getenv("POSTGRES_DB", "sdmxdb")
        self.postgres_password = self._read_file(
            os.getenv("POSTGRES_PASSWORD_FILE", "/tmp/secrets/POSTGRES_PASSWORD.txt")
        )

    @staticmethod
    def _read_file(path: str) -> str:
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except Exception:
            return ""


settings = Settings()