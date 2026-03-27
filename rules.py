def rule_poisoned_high_rate(packet: dict) -> bool:
    """Detect poisoned high‑rate attacks."""
    if packet.get('timestampDiff', 0) < -1000:
        return True
    if packet.get('stDiff', 0) < -1000:
        return True
    if packet.get('sqDiff', 0) < -100:
        return True
    return False


def rule_grayhole(packet: dict) -> bool:
    """Detect grayhole (no state change, no length change)."""
    if packet.get('stDiff', 0) == 0 and packet.get('sqDiff', 0) == 0 and packet.get('gooseLengthDiff', 0) == 0:
        return True
    return False


def rule_inverse_replay(packet: dict) -> bool:
    """Detect inverse replay (large forward time jumps)."""
    if packet.get('tDiff', 0) > 1000 and packet.get('timestampDiff', 0) > 1000:
        return True
    return False


def rule_masquerade_fake_fault(packet: dict) -> bool:
    """Detect masquerade / fake fault (low sequence numbers with status flag)."""
    if packet.get('SqNum', 0) < 10 and packet.get('StNum', 0) < 100 and packet.get('cbStatus', 0) == 1.0:
        return True
    return False


def rule_unexpected_sequence(packet: dict) -> bool:
    """Detect unexpected large jumps in sequence or state numbers."""
    if packet.get('sqDiff', 0) > 10 or packet.get('stDiff', 0) > 100:
        return True
    return False


def rule_unusual_length(packet: dict) -> bool:
    """Detect abnormal GOOSE length variations."""
    if packet.get('gooseLengthDiff', 0) > 100:
        return True
    return False
