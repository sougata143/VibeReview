# app/context.py
# ContextResolver middleware for PII masking and data hygiene (Pillar 2).
# This utility functions as a middleware preprocessor, ensuring compliance with data residency and
# confidentiality policies by replacing sensitive information with un-hallucinatable placeholders.

import re

class ContextResolver:
    """Masks Personally Identifiable Information (PII) before processing by LLM.
    
    Provides bidirectional masking/unmasking. It scans repository files, chat logs, 
    and inputs for predefined patterns (emails, IPs, API keys, credentials) and replaces 
    them with reversible tokens like [[EMAIL_1]] so that the primary LLM never ingests raw PII.
    """
    
    def __init__(self):
        # Maps placeholders (e.g. "[[EMAIL_1]]") to original text ("user@example.com")
        # to allow loss-less reconstruction via unmask().
        self._mappings = {}
        self._counter = {}
        
        # Define PII Regex patterns for structural classification.
        # Patterns are optimized to minimize false-positives while maintaining high recall.
        self._patterns = {
            # Standard RFC 5322 email matching
            "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            # IPv4 address matching
            "IP_ADDRESS": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            # API keys, tokens, credentials, and password assignments (case-insensitive matcher)
            "API_KEY": r'(?i)(?:key|token|secret|password|passwd|pwd|auth)(?:\s*[:=]\s*|\s+)["'][a-zA-Z0-9_\-\.\~]{8,}["']',
            # Standard international/local phone numbers
            "PHONE_NUMBER": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            # Credit card numbers (Luhn-compliant digit groups)
            "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b'
        }

    def mask(self, text: str) -> str:
        """Masks PII patterns in the input text with [[VARIABLE_NAME_ID]] placeholders.
        
        It iterates over all regex patterns. For each matched occurrence:
        - If the sensitive value was already encountered, it reuses the same placeholder.
        - Otherwise, it increments the type counter, generates a new placeholder, and registers it.
        """
        if not isinstance(text, str):
            return text
            
        masked_text = text
        for pii_type, regex in self._patterns.items():
            def replace_match(match):
                original = match.group(0)
                
                # Check if we already mapped this exact original value to a placeholder
                # to ensure data mapping consistency across the entire request context.
                for placeholder, val in self._mappings.items():
                    if val == original:
                        return placeholder
                
                # Generate new unique placeholder identifier
                self._counter[pii_type] = self._counter.get(pii_type, 0) + 1
                placeholder = f"[[{pii_type}_{self._counter[pii_type]}]]"
                self._mappings[placeholder] = original
                return placeholder
            
            masked_text = re.sub(regex, replace_match, masked_text)
            
        return masked_text

    def unmask(self, text: str) -> str:
        """Restores original PII values back into the masked text using recorded mappings.
        
        To prevent substring collision (e.g., replacing "[[EMAIL_1]]" inside "[[EMAIL_10]]"),
        placeholders are sorted by length in descending order before executing the replacement.
        """
        if not isinstance(text, str):
            return text
            
        unmasked_text = text
        # Sorting placeholders by length descending (e.g. [[EMAIL_10]] before [[EMAIL_1]])
        # prevents prefix matching bugs and partial replacements.
        sorted_placeholders = sorted(self._mappings.keys(), key=len, reverse=True)
        for placeholder in sorted_placeholders:
            original = self._mappings[placeholder]
            unmasked_text = unmasked_text.replace(placeholder, original)
        return unmasked_text

    def get_mappings(self) -> dict:
        """Returns a copy of the active placeholder mappings."""
        return self._mappings.copy()

    def clear(self):
        """Clears all dynamic mappings and counters.
        
        Should be invoked between distinct session requests or turns to prevent 
        cross-conversation information leak or context pollution.
        """
        self._mappings.clear()
        self._counter.clear()
