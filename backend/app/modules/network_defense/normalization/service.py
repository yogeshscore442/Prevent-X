"""
PREVENT-X Virtual Patch Normalization Integration Service
Connects payload canonicalization with Intelligent Virtual Patching (MOD-08).
Evaluates both raw and normalized text representations so evasions cannot bypass regex rules.
"""

import logging
import re
from typing import List, Optional, Tuple

from backend.app.models.virtual_patch import VirtualPatchRule
from backend.app.modules.network_defense.normalization.normalizer import (
    NormalizedPayload,
    PayloadNormalizer,
    payload_normalizer,
)

logger = logging.getLogger("preventx.network_defense.normalization.service")


class NormalizationPatchIntegrationService:
    def __init__(self, normalizer: Optional[PayloadNormalizer] = None):
        self.normalizer = normalizer or payload_normalizer

    def evaluate_payload_against_patch_rules(
        self,
        raw_payload: str,
        rules: List[VirtualPatchRule],
    ) -> Tuple[bool, Optional[VirtualPatchRule], NormalizedPayload]:
        """
        Evaluates payload through both raw and canonicalized representations.
        Returns: (is_blocked, matched_rule, normalized_metadata)
        """
        norm_result = self.normalizer.normalize(raw_payload)

        # Inspect both raw text and normalized text
        inspection_targets = [norm_result.raw_text, norm_result.normalized_text]
        # Also inspect any decoded Base64 fragments
        inspection_targets.extend(norm_result.extracted_base64_fragments)

        for rule in rules:
            pattern = getattr(rule, "pattern", None) or getattr(rule, "match_conditions", None)
            if not pattern:
                continue
            rule_label = getattr(rule, "rule_name", getattr(rule, "name", "rule"))
            try:
                rx = re.compile(pattern, re.IGNORECASE)
                for target in inspection_targets:
                    if rx.search(target):
                        logger.info(
                            "Virtual patch rule '%s' triggered on payload (obfuscation detected: %s)",
                            rule_label,
                            norm_result.obfuscation_detected,
                        )
                        return True, rule, norm_result
            except re.error as ex:
                logger.warning("Invalid regex pattern in rule '%s': %s", rule_label, ex)

        return False, None, norm_result


normalization_patch_service = NormalizationPatchIntegrationService()
