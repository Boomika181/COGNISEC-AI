"""
Security Sanitization Pipeline for Agent Inputs.
Enforces the Zero-Trust data boundary:
- Never expose passwords, OTPs, private cognitive answers, raw keystrokes, or confidential vault contents.
- Mask PII (emails, IPs).
"""
import re
from typing import Dict, Any, List, Optional

EMAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
IPV4_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")

# Keys that must be entirely redacted or suppressed
STRICTLY_PROHIBITED_KEYS = {
    "password", "password_hash", "hashed_password", "current_password", "new_password",
    "otp", "otp_code", "recovery_code", "secret", "secret_key", "api_key", "gemini_api_key",
    "jwt", "access_token", "refresh_token", "session_token",
    "token", "bearer", "authorization",
    "private_answer", "private_response", "answer_hash", "expected_answer",
    "cognitive_answer", "security_answer",
    "gesture_pattern", "gesture_hash", "pattern_hash", "gesture_nodes",
    "gesture_secret", "gesture_trace", "raw_gesture",
    "symbol_sequence", "sequence_hash", "symbol_ids",
    "raw_keystrokes", "raw_keys", "key_events", "key_codes", "key_timestamps",
    "medical_notes", "diagnosis", "prescriptions", "patient_ssn",
    "patient_record", "health_record", "medical_history",
    "exam_questions", "answer_key", "student_responses", "exam_answers", "exam_paper",
    "vault_secret", "vault_data", "confidential_data",
    "credit_card", "card_number", "cvv", "payment_pin"
}


class Sanitizer:
    """Deterministic security sanitizer for agent input contexts."""

    @classmethod
    def mask_email(cls, email: Optional[str]) -> str:
        """Masks an email address: bob.smith@example.com -> b***h@example.com."""
        if not email or not isinstance(email, str):
            return "[REDACTED_EMAIL]"
        match = EMAIL_REGEX.match(email.strip())
        if not match:
            return "[INVALID_EMAIL]"
        user, domain = match.groups()
        if len(user) <= 2:
            masked_user = user[0] + "***"
        else:
            masked_user = user[0] + "***" + user[-1]
        return f"{masked_user}@{domain}"

    @classmethod
    def mask_ip(cls, ip: Optional[str]) -> str:
        """Masks an IP address: 192.168.1.45 -> 192.168.1.***."""
        if not ip or not isinstance(ip, str):
            return "[REDACTED_IP]"
        return IPV4_REGEX.sub(r"\1.***", ip.strip())

    @classmethod
    def neutralize_prompt_injection(cls, text: Optional[str]) -> str:
        """
        Neutralizes adversarial prompt injection patterns embedded within
        untrusted user or database strings (e.g., device nicknames, user names).
        Defangs directive markers and control syntax.
        """
        if not text or not isinstance(text, str):
            return ""
        
        # Defang standard injection keywords and control markers
        injection_patterns = [
            (r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", "[DEFANGED_PROMPT_INJECTION]"),
            (r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", "[DEFANGED_PROMPT_INJECTION]"),
            (r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak)\s+mode\b", "[DEFANGED_PROMPT_INJECTION]"),
            (r"(?i)\bsystem\s*:\s*", "[DEFANGED_SYSTEM_DIRECTIVE]: "),
            (r"(?i)<\s*/?\s*(?:system|instruction|prompt_override)[^>]*>", "[DEFANGED_TAG]"),
        ]
        sanitized = text
        for pattern, repl in injection_patterns:
            sanitized = re.sub(pattern, repl, sanitized)
        return sanitized

    @classmethod
    def sanitize_text(cls, text: Optional[str]) -> str:
        """Sanitizes raw text by scrubbing PII (email, IP) and defanging prompt injections."""
        if not text or not isinstance(text, str):
            return ""
        masked = EMAIL_REGEX.sub(lambda m: cls.mask_email(m.group(0)), text)
        masked = IPV4_REGEX.sub(r"\1.***", masked)
        return cls.neutralize_prompt_injection(masked)

    @classmethod
    def sanitize_dict(cls, data: Any) -> Any:
        """
        Recursively sanitizes a dictionary or list, stripping prohibited secret keys,
        masking sensitive fields, and defanging potential prompt injection strings.
        """
        if isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                k_lower = str(k).lower().strip()
                if any(bad_key in k_lower for bad_key in STRICTLY_PROHIBITED_KEYS):
                    sanitized[k] = "[REDACTED_SECRET]"
                elif "email" in k_lower and isinstance(v, str):
                    sanitized[k] = cls.mask_email(v)
                elif "ip" in k_lower and isinstance(v, str):
                    sanitized[k] = cls.mask_ip(v)
                else:
                    sanitized[k] = cls.sanitize_dict(v)
            return sanitized
        elif isinstance(data, list):
            return [cls.sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            return cls.sanitize_text(data)
        return data

