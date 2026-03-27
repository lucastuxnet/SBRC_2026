## grayhole


def rule_grayhole_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('StNum') == 0.0 and packet.get('SqNum') != 0.0

def rule_grayhole_sqnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('sqDiff', 0) > 10.0 or packet.get('stDiff', 0) > 10.0

def rule_grayhole_timediff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    td = packet.get('timestampDiff', 0)
    return td > 0.1 or td < -0.1

def rule_grayhole_goose_length(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('gooseLengthDiff', 0) > 10.0

def rule_grayhole_apdu_size(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('apduSizeDiff', 0) > 10.0

def rule_grayhole_frame_length(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('frameLengthDiff', 0) > 10.0

def rule_grayhole_combined(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    if packet.get('StNum') == 0.0 and packet.get('SqNum') != 0.0:
        return True
    if packet.get('sqDiff', 0) > 50.0 or packet.get('stDiff', 0) > 50.0:
        return True
    td = packet.get('timestampDiff', 0)
    if td > 1.0 or td < -1.0:
        return True
    if abs(packet.get('gooseLen', 0) - packet.get('APDUSize', 0)) > 100.0:
        return True
    return False


## high_StNum


def rule_high_StNum_StNum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet['StNum'] > 50000

def rule_high_StNum_stDiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet['stDiff'] > 1000

def rule_high_StNum_stDiff_and_StNum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet['stDiff'] > 1000 and packet['StNum'] > 50000

def rule_high_StNum_timeFromLastChange(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet['timeFromLastChange'] < 1

def rule_high_StNum_combined(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet['StNum'] > 50000 and packet['stDiff'] > 1000 and packet['timeFromLastChange'] < 1


## injection


def rule_injection_stdiff(packet: dict) -> bool:
    """Detect injection when StNum difference is unusually negative."""
    return packet.get('stDiff', 0) < -10

def rule_injection_sqdiff(packet: dict) -> bool:
    """Detect injection when SqNum difference is unusually negative."""
    return packet.get('sqDiff', 0) < -10

def rule_injection_timestampdiff(packet: dict) -> bool:
    """Detect injection when timestamp difference is abnormally large."""
    return packet.get('timestampDiff', 0) > 100

def rule_injection_tdiff(packet: dict) -> bool:
    """Detect injection when time delta between packets is unusually high."""
    return packet.get('tDiff', 0) > 0.1

def rule_injection_timefromlastchange(packet: dict) -> bool:
    """Detect injection when time from last change spikes."""
    return packet.get('timeFromLastChange', 0) > 100

def rule_injection_combined(packet: dict) -> bool:
    """Combined heuristic for injection detection."""
    return (
        packet.get('stDiff', 0) < -10 or
        packet.get('sqDiff', 0) < -10 or
        packet.get('timestampDiff', 0) > 100 or
        packet.get('tDiff', 0) > 0.1 or
        packet.get('timeFromLastChange', 0) > 100
    )



## inverse_replay


def rule_inverse_replay_stnum(packet: dict) -> bool:
    """Detects inverse replay based on unusually high StNum and large timestamp differences."""
    return packet.get('StNum', 0) > 300 and packet.get('timestampDiff', 0) > 1000

def rule_inverse_replay_sqnum(packet: dict) -> bool:
    """Detects inverse replay when SqNum is unusually high and stDiff is negative."""
    return packet.get('SqNum', 0) > 40 and packet.get('stDiff', 0) < 0

def rule_inverse_replay_tdiff(packet: dict) -> bool:
    """Detects inverse replay using large tDiff and timeFromLastChange values."""
    return packet.get('tDiff', 0) > 1000 and packet.get('timeFromLastChange', 0) > 1000

def rule_inverse_replay_stdiff_sqdiff(packet: dict) -> bool:
    """Detects inverse replay when stDiff is negative and sqDiff is positive."""
    return packet.get('stDiff', 0) < 0 and packet.get('sqDiff', 0) > 0

def rule_inverse_replay_combined(packet: dict) -> bool:
    """Combined heuristic for inverse replay detection."""
    high_stnum = packet.get('StNum', 0) > 300
    high_sqnum = packet.get('SqNum', 0) > 40
    large_timestamp = packet.get('timestampDiff', 0) > 1000
    negative_stdiff = packet.get('stDiff', 0) < 0
    return (high_stnum or high_sqnum) and large_timestamp and negative_stdiff


## masquerade_fake_fault


def rule_masquerade_fake_fault_tdiff(packet: dict) -> bool:
    """Retorna True se o campo tDiff indicar comportamento suspeito."""
    return abs(packet.get('tDiff', 0)) > 0.1

def rule_masquerade_fake_fault_timestampdiff(packet: dict) -> bool:
    """Retorna True se o campo timestampDiff indicar comportamento suspeito."""
    return abs(packet.get('timestampDiff', 0)) > 0.1

def rule_masquerade_fake_fault_stdiff(packet: dict) -> bool:
    """Retorna True se o campo stDiff indicar comportamento suspeito."""
    return abs(packet.get('stDiff', 0)) > 10

def rule_masquerade_fake_fault_sqdiff(packet: dict) -> bool:
    """Retorna True se o campo sqDiff indicar comportamento suspeito."""
    return abs(packet.get('sqDiff', 0)) > 10

def rule_masquerade_fake_fault_combined(packet: dict) -> bool:
    """Retorna True se qualquer um dos indicadores acima sinalizar ataque."""
    return (
        rule_masquerade_fake_fault_tdiff(packet) or
        rule_masquerade_fake_fault_timestampdiff(packet) or
        rule_masquerade_fake_fault_stdiff(packet) or
        rule_masquerade_fake_fault_sqdiff(packet)
    )


## masquerade_fake_normal


def rule_masquerade_fake_normal_high_stnum(packet: dict) -> bool:
    """Detects packets with unusually high State Number (StNum) typical of masquerade attacks."""
    return packet.get('StNum', 0) > 1000

def rule_masquerade_fake_normal_large_sqdiff(packet: dict) -> bool:
    """Detects packets with large absolute Sequence Number difference (sqDiff)."""
    return abs(packet.get('sqDiff', 0)) > 5000

def rule_masquerade_fake_normal_large_stdiff(packet: dict) -> bool:
    """Detects packets with large absolute State Number difference (stDiff)."""
    return abs(packet.get('stDiff', 0)) > 300

def rule_masquerade_fake_normal_zero_timestampdiff(packet: dict) -> bool:
    """Detects packets where timestampDiff is zero while other fields show anomalies."""
    return packet.get('timestampDiff', 1) == 0 and (
        packet.get('StNum', 0) > 1000 or
        abs(packet.get('sqDiff', 0)) > 5000 or
        abs(packet.get('stDiff', 0)) > 300
    )

def rule_masquerade_fake_normal_unusual_delay(packet: dict) -> bool:
    """Detects packets with unusually high delay values not seen in normal traffic."""
    return packet.get('delay', 0) > 0.1

def rule_masquerade_fake_normal_combined(packet: dict) -> bool:
    """Combined heuristic for masquerade_fake_normal detection."""
    return (
        packet.get('StNum', 0) > 1000 or
        abs(packet.get('sqDiff', 0)) > 5000 or
        abs(packet.get('stDiff', 0)) > 300 or
        packet.get('timestampDiff', 1) == 0 or
        packet.get('delay', 0) > 0.1
    )


## poisoned_high_rate


def rule_poisoned_high_rate_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('StNum', 0) > 1000 and packet.get('timestampDiff', 0) > 1

def rule_poisoned_high_rate_sqnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('SqNum', 0) == 1.0 and packet.get('timestampDiff', 0) > 100

def rule_poisoned_high_rate_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('tDiff', 0) > 5 and packet.get('StNum', 0) > 1000

def rule_poisoned_high_rate_timefromlastchange(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return packet.get('timeFromLastChange', 0) > 1000 and packet.get('StNum', 0) > 1000

def rule_poisoned_high_rate_combined(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    return (
        packet.get('StNum', 0) > 1000 and
        packet.get('SqNum', 0) == 1.0 and
        packet.get('timestampDiff', 0) > 100
    )


## random_replay


def rule_random_replay_stnum_sqnum_mismatch(packet: dict) -> bool:
    """Detects mismatch between StNum and SqNum typical of replay attacks."""
    return abs(packet['StNum'] - packet['SqNum']) > 10

def rule_random_replay_large_sqdiff(packet: dict) -> bool:
    """Detects unusually large sqDiff values."""
    return packet.get('sqDiff', 0) > 5

def rule_random_replay_large_stdiff(packet: dict) -> bool:
    """Detects unusually large stDiff values."""
    return packet.get('stDiff', 0) > 5

def rule_random_replay_timestamp_anomaly(packet: dict) -> bool:
    """Detects abnormal timestamp differences and tDiff values."""
    return packet.get('timestampDiff', 0) < 0.1 and packet.get('tDiff', 0) > 0.1

def rule_random_replay_combined(packet: dict) -> bool:
    """Combines several indicators to flag a replay attack."""
    return (
        abs(packet['StNum'] - packet['SqNum']) > 10 and
        packet.get('sqDiff', 0) > 5 and
        packet.get('stDiff', 0) > 5 and
        packet.get('timestampDiff', 0) < 0.1 and
        packet.get('tDiff', 0) > 0.1
    )
