# apps/api/detector_config.py
"""
Centralized Configuration for FlowCrypid Behavioral Detectors.
Eliminates magic numbers and defines tunable detection thresholds.
"""

class DetectorConfig:
    # Volume thresholds
    LARGE_TRANSFER_BYTES: int = 50 * 1024 * 1024  # 50 MB
    ASYMMETRY_RATIO_MIN: float = 10.0             # Fwd/Rev byte ratio

    # Timing / Beaconing thresholds
    BEACONING_CV_MAX: float = 0.15                # Low coefficient of variation
    MIN_BEACON_PACKETS: int = 10

    # DNS thresholds
    DNS_ENTROPY_MIN: float = 4.0                  # High Shannon entropy for DGA detection
    DNS_NXDOMAIN_MIN: int = 5

    # Network rate thresholds
    PACKET_RATE_MAX: float = 500.0                # Packets per second

    # Scanning thresholds
    SCAN_UNIQUE_PORTS_MIN: int = 15