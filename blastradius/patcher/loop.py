"""PatchLoop — generate, verify, retry: the verification loop.

Up to ``max_attempts`` iterations:
1. generate a patch (with prior failure context after the first attempt)
2. verify it (syntax / exploit / regression)
3. confidence == 100 -> done; otherwise regenerate
If all attempts fail, the result is flagged for human review.
"""

from dataclasses import dataclass
from typing import Optional

from blastradius.hunter.scanner import Finding
from blastradius.patcher.generator import Patch, PatchGenerator
from blastradius.patcher.verifier import PatchVerifier, VerificationResult


@dataclass
class PatchResult:
    """Final outcome of the patch loop."""
    patch: Optional[Patch]
    verification: Optional[VerificationResult]
    attempts: int
    needs_human: bool


class PatchLoop:
    """Retry loop for patch generation + verification."""

    def __init__(
        self,
        generator: Optional[PatchGenerator] = None,
        verifier: Optional[PatchVerifier] = None,
        max_attempts: int = 3,
    ):
        self.generator = generator or PatchGenerator()
        self.verifier = verifier or PatchVerifier()
        self.max_attempts = max_attempts

    def run(self, finding: Finding) -> PatchResult:
        """Generate + verify up to ``max_attempts`` times.

        Returns a PatchResult; ``needs_human`` is True when every attempt
        failed to reach 100% confidence.
        """
        failures: list = []
        patch: Optional[Patch] = None
        verification: Optional[VerificationResult] = None

        for attempt in range(1, self.max_attempts + 1):
            failure_context = "\n".join(failures)
            patch = self.generator.generate_patch(finding, failure_context=failure_context)
            verification = self.verifier.verify(finding, patch)
            if verification.confidence == 100:
                return PatchResult(patch, verification, attempt, needs_human=False)
            failures.append(
                f"Attempt {attempt}: {verification.failure_reasons or 'confidence below 100'}"
            )

        return PatchResult(patch, verification, self.max_attempts, needs_human=True)
