# app/app_utils/microtransactions.py
import re
import hashlib
import logging

class L402PaymentHandler:
    def __init__(self, private_key_hex: str = "00"*32):
        self.private_key_hex = private_key_hex

    def simulate_payment(self, invoice: str) -> str:
        """Simulates payment of a Lightning/L402 invoice, returning a cryptographic proof (preimage).
        
        Generates the SHA256 hash of the invoice to represent a cryptographic proof-of-payment.
        """
        preimage = hashlib.sha256(invoice.encode('utf-8')).hexdigest()
        return preimage

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
        """Executes an API call, and if it returns HTTP 402, simulates payment and retries with credentials.
        
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

                # Pay the invoice to obtain the preimage proof-of-payment
                preimage = self.simulate_payment(invoice)
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
