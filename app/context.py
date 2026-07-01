import re

class ContextResolver:
    def __init__(self):
        self._mappings = {}
        self._counter = {}
        # Stores whether the original value was quoted for restore
        self._quoted_status = {}
        
        self._patterns = {
            "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            "IP_ADDRESS": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "API_KEY": r"(?i)(?:key|token|secret|password|passwd|pwd|authentication|auth)(?:\s*[:=]\s*|\s+)(?:['\"][a-zA-Z0-9_\-\.\~]{8,}['\"]|[a-zA-Z0-9_\-\.\~]{8,})",
            "PHONE_NUMBER": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b'
        }

    def mask(self, text: str) -> str:
        if not isinstance(text, str):
            return text
            
        masked_text = text
        for pii_type, regex in self._patterns.items():
            def replace_match(match):
                original = match.group(0)
                label_match = re.search(r"(?i)(key|token|secret|password|passwd|pwd|authentication|auth)(\s*[:=]\s*|\s+)", original)
                if label_match:
                    label = label_match.group(0)
                    raw_val = original[len(label):]
                    is_quoted = len(raw_val) > len(raw_val.strip('\'"'))
                    value = raw_val.strip('\'"')
                    
                    for placeholder, val in self._mappings.items():
                        if val == value:
                            return label + placeholder
                    
                    self._counter[pii_type] = self._counter.get(pii_type, 0) + 1
                    placeholder = f"[[{pii_type}_{self._counter[pii_type]}]]"
                    self._mappings[placeholder] = value
                    self._quoted_status[placeholder] = is_quoted
                    return label + placeholder
                
                return original # No change if label not found
            
            masked_text = re.sub(regex, replace_match, masked_text)
            
        return masked_text

    def unmask(self, text: str) -> str:
        if not isinstance(text, str):
            return text
            
        unmasked_text = text
        sorted_placeholders = sorted(self._mappings.keys(), key=len, reverse=True)
        for placeholder in sorted_placeholders:
            original = self._mappings[placeholder]
            if self._quoted_status.get(placeholder, False):
                original = f'"{original}"'
            unmasked_text = unmasked_text.replace(placeholder, original)
        return unmasked_text

    def get_mappings(self) -> dict:
        return self._mappings.copy()

    def clear(self):
        self._mappings.clear()
        self._counter.clear()
        self._quoted_status.clear()
