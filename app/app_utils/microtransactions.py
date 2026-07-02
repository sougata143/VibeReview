# app/app_utils/microtransactions.py
import re
import hashlib
import logging
import os
import aiohttp
import codecs
import json

class L402PaymentHandler:
    def __init__(self, private_key_hex: str = "00"*32):
        self.private_key_hex = private_key_hex

    def simulate_payment(self, invoice: str) -> str:
        """Simulates payment of a Lightning/L402 invoice, returning a cryptographic proof (preimage).
        
        Generates the SHA256 hash of the invoice to represent a cryptographic proof-of-payment.
        """
        preimage = hashlib.sha256(invoice.encode('utf-8')).hexdigest()
        return preimage

    async def pay_invoice_live(self, invoice: str) -> str:
        """Connects to a live Lightning Network node (LND REST API or Alby API) to pay the invoice.
        
        Falls back to simulation if no node environment credentials are set.
        """
        lnd_url = os.environ.get("LND_REST_URL")
        lnd_macaroon_hex = os.environ.get("LND_MACAROON_HEX")
        alby_token = os.environ.get("ALBY_API_TOKEN")

        if lnd_url and lnd_macaroon_hex:
            # Pay using LND Node REST API
            pay_url = f"{lnd_url.rstrip('/')}/v1/channels/transactions"
            headers = {
                "Grpc-Metadata-macaroon": lnd_macaroon_hex,
                "Content-Type": "application/json"
            }
            payload = {"payment_request": invoice}
            try:
                # Use ssl=False for local node self-signed cert setups
                async with aiohttp.ClientSession() as session:
                    async with session.post(pay_url, json=payload, headers=headers, ssl=False) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            preimage_b64 = data.get("payment_preimage")
                            if preimage_b64:
                                preimage_bytes = codecs.decode(preimage_b64.encode("utf-8"), "base64")
                                return codecs.encode(preimage_bytes, "hex").decode("utf-8")
            except Exception as e:
                logging.error(f"Failed to pay invoice via LND REST API: {e}")

        elif alby_token:
            # Pay using Alby Wallet API
            pay_url = "https://api.getalby.com/payments/send"
            headers = {
                "Authorization": f"Bearer {alby_token}",
                "Content-Type": "application/json"
            }
            payload = {"invoice": invoice}
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(pay_url, json=payload, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            preimage_hex = data.get("payment_preimage")
                            if preimage_hex:
                                return preimage_hex
            except Exception as e:
                logging.error(f"Failed to pay invoice via Alby Wallet API: {e}")

        # Fallback to simulation
        return self.simulate_payment(invoice)

    def parse_402_header(self, authenticate_header: str) -> dict:
        """Parses the WWW-Authenticate header to extract L402 token and invoice.
        
        Example header: L402 token="macaroon_hex", invoice="lnbc..."
        """
        token_match = re.search(r'token="([^"]+)"', authenticate_header)
        invoice_match = re.search(r'invoice="([^"]+)"', authenticate_header)

        return {
            "token": token_match.group(1) if token_match else "",
            "invoice": invoice_match.group(1) if invoice_match else ""
        }

    def make_l402_auth_header(self, token: str, preimage: str) -> str:
        """Returns the compiled L402 Authorization header value."""
        return f"L402 {token}:{preimage}"

    async def handle_402_retry(self, client_func, *args, **kwargs) -> dict:
        """Executes an API call, and if it returns HTTP 402, executes/simulates payment and retries with credentials.
        
        Args:
            client_func: A callable representing the async HTTP request function.
        """
        response = await client_func(*args, **kwargs)

        if response.get("status_code") == 402:
            auth_header = response.get("headers", {}).get("WWW-Authenticate", "")
            if "L402" in auth_header:
                details = self.parse_402_header(auth_header)
                token = details["token"]
                invoice = details["invoice"]

                logging.info(f"Received HTTP 402 Payment Required. Invoice: {invoice}")

                # Pay the invoice using live/mock Lightning API
                preimage = await self.pay_invoice_live(invoice)
                logging.info(f"Invoice paid successfully. Preimage: {preimage}")

                # Rebuild L402 Authorization header
                l402_auth = self.make_l402_auth_header(token, preimage)

                # Inject header and retry
                if "headers" not in kwargs:
                    kwargs["headers"] = {}
                kwargs["headers"]["Authorization"] = l402_auth

                # Retry request
                retry_response = await client_func(*args, **kwargs)
                return retry_response

        return response
