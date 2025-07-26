"""
Text analysis for determining if decrypted content is meaningful English.

This module provides sophisticated analysis beyond simple letter frequency,
including statistical confidence measures, multiple scoring metrics, and
automatic text normalization for better accuracy.
"""

from dataclasses import dataclass


@dataclass
class TextAnalysisResult:
    """Result of text analysis with multiple confidence metrics."""

    frequency_score: float
    printable_ratio: float
    space_ratio: float
    english_probability: float
    confidence_level: str

    def __str__(self) -> str:
        return f"English probability: {self.english_probability:.1%} ({self.confidence_level})"


class EnglishAnalyzer:
    """Analyzer for determining if text is likely to be English."""

    # Expected ratios for English text
    EXPECTED_SPACE_RATIO = 0.13
    EXPECTED_PRINTABLE_RATIO = 0.95

    # Calibrated thresholds (based on actual testing with various English texts)
    ENGLISH_FREQUENCY_MEAN = 0.25  # Lower mean based on real English text
    ENGLISH_FREQUENCY_STD = 0.15  # Adjusted standard deviation

    def __init__(self, normalize: bool = True) -> None:
        """Initialize with optional custom frequency scoring function and normalization.

        Args:
            frequency_scorer: Custom frequency scoring function (defaults to xorxer.score_text)
            normalize: Whether to normalize text before analysis (lowercase, reduce whitespace)
        """
        from ciphergeist.encrypters.xorxer import score_text

        self.frequency_scorer = score_text
        self.normalize = normalize

    def normalize_text(self, text: bytes) -> bytes:
        """Normalize text for better analysis.

        - Converts to lowercase (critical since frequency scorer only counts lowercase)
        - Reduces multiple whitespace to single spaces
        - Strips leading/trailing whitespace
        """
        if not self.normalize:
            return text

        try:
            # Decode to string for easier processing
            text_str = text.decode("utf-8", errors="ignore")

            # Convert to lowercase (critical for frequency analysis)
            text_str = text_str.lower()

            # Reduce multiple whitespace to single spaces
            import re

            text_str = re.sub(r"\s+", " ", text_str)

            # Strip leading/trailing whitespace
            text_str = text_str.strip()

            return text_str.encode("utf-8")
        except Exception:
            return text

    def analyze(self, text: bytes) -> TextAnalysisResult:
        """Perform comprehensive analysis of text with optional normalization."""
        if not text:
            return TextAnalysisResult(
                frequency_score=float("inf"),
                printable_ratio=0.0,
                space_ratio=0.0,
                english_probability=0.0,
                confidence_level="No text",
            )

        # Normalize text if enabled (default)
        if self.normalize:
            text = self.normalize_text(text)

        # Calculate individual metrics
        frequency_score = self.frequency_scorer(text)
        printable_ratio = self._calculate_printable_ratio(text)
        space_ratio = self._calculate_space_ratio(text)

        # Calculate overall English probability
        english_probability = self._calculate_english_probability(
            frequency_score, printable_ratio, space_ratio, len(text)
        )

        confidence_level = self._get_confidence_level(english_probability)

        return TextAnalysisResult(
            frequency_score=frequency_score,
            printable_ratio=printable_ratio,
            space_ratio=space_ratio,
            english_probability=english_probability,
            confidence_level=confidence_level,
        )

    def _calculate_printable_ratio(self, text: bytes) -> float:
        """Calculate ratio of printable ASCII characters."""
        printable_count = sum(1 for b in text if 32 <= b <= 126)
        return printable_count / len(text)

    def _calculate_space_ratio(self, text: bytes) -> float:
        """Calculate ratio of space characters."""
        space_count = text.count(b" ")
        return space_count / len(text)

    def _calculate_english_probability(
        self, frequency_score: float, printable_ratio: float, space_ratio: float, text_length: int
    ) -> float:
        """Calculate probability that text is English using multiple factors."""

        # Start with frequency-based probability (more lenient scoring)
        freq_z_score = (frequency_score - self.ENGLISH_FREQUENCY_MEAN) / self.ENGLISH_FREQUENCY_STD
        freq_prob = max(0.01, min(0.99, 1 / (1 + abs(freq_z_score) * 0.5)))  # Less harsh penalty

        # Adjust based on printable character ratio (more lenient)
        printable_penalty = max(0.3, printable_ratio / self.EXPECTED_PRINTABLE_RATIO)

        # Adjust based on space ratio (more tolerant of variation)
        space_diff = abs(space_ratio - self.EXPECTED_SPACE_RATIO)
        space_penalty = max(0.7, 1 - (space_diff * 2))  # Less harsh space penalty

        # Combine all factors (without word boost for better short text handling)
        probability = freq_prob * printable_penalty * space_penalty

        return max(0.01, min(0.99, probability))

    def _get_confidence_level(self, probability: float) -> str:
        """Convert probability to human-readable confidence level."""
        if probability >= 0.8:
            return "Very High"
        elif probability >= 0.6:
            return "High"
        elif probability >= 0.4:
            return "Medium"
        elif probability >= 0.2:
            return "Low"
        else:
            return "Very Low"


def analyze_english_probability(text: bytes) -> TextAnalysisResult:
    """Convenience function for quick English analysis."""
    analyzer = EnglishAnalyzer()
    return analyzer.analyze(text)


def compare_candidates(candidates: list[bytes]) -> list[TextAnalysisResult]:
    """Analyze multiple candidate texts and return sorted by English probability."""
    analyzer = EnglishAnalyzer()
    results = [analyzer.analyze(candidate) for candidate in candidates]
    return sorted(results, key=lambda r: r.english_probability, reverse=True)
