def rule_stnum_anomaly(packet: dict) -> bool:
    return packet.get('StNum', 0) < 0 or packet.get('StNum', 0) > 1000

def rule_sqnum_diff_anomaly(packet: dict) -> bool:
    return packet.get('sqDiff', 0) < -10 or packet.get('sqDiff', 0) > 10

def rule_timestamp_diff_anomaly(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) < -1 or packet.get('timestampDiff', 0) > 1

def rule_goose_length_diff_anomaly(packet: dict) -> bool:
    return packet.get('gooseLengthDiff', 0) != 0

def rule_apdu_size_diff_anomaly(packet: dict) -> bool:
    return packet.get('apduSizeDiff', 0) != 0

def rule_cbstatus_diff_anomaly(packet: dict) -> bool:
    return packet.get('cbStatusDiff', 0) != 0

def rule_high_rate_of_change(packet: dict) -> bool:
    return packet.get('timeFromLastChange', 0) < 0.01

def rule_poisoned_high_rate(packet: dict) -> bool:
    return (abs(packet.get('sqDiff', 0)) > 50 or abs(packet.get('stDiff', 0)) > 5000) and packet.get('timeFromLastChange', 0) < 0.1

def rule_grayhole(packet: dict) -> bool:
    return packet.get('StNum', 0) > 0 and packet.get('SqNum', 0) == 0

def rule_inverse_replay(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 10 and packet.get('sqDiff', 0) == 0

def rule_masquerade_fake_fault(packet: dict) -> bool:
    return packet.get('StNum', 0) > 0 and packet.get('SqNum', 0) > 0 and packet.get('cbStatus', 0) == 1.0