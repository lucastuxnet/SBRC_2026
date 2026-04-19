# Regras de detecção geradas pelo LLM (limpas)
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    stnum = packet.get('StNum', 0)
    stnum_diff = packet.get('stDiff', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    if stnum_diff > 5 and timestamp_diff < 5:
        return True
    if stnum_diff > 1000 and timestamp_diff < 60:
        return True
    return False

def rule_high_StNum_sqnum_reset_pattern(packet: dict) -> bool:
    sqnum = packet.get('SqNum', 0)
    sqnum_diff = packet.get('sqDiff', 0)
    stnum_diff = packet.get('stDiff', 0)
    if sqnum_diff > 2 and stnum_diff > 1:
        return True
    if sqnum == 0 and stnum_diff > 1:
        return True
    return False

def rule_high_StNum_abnormal_cbstatus_shift(packet: dict) -> bool:
    cbstatus = packet.get('cbStatus', 0)
    cbstatus_diff = packet.get('cbStatusDiff', 0)
    stnum_diff = packet.get('stDiff', 0)
    if cbstatus_diff > 0.5 and stnum_diff > 1:
        return True
    if cbstatus > 0.5 and stnum_diff > 5:
        return True
    return False

def rule_high_StNum_static_payload_size(packet: dict) -> bool:
    goose_length_diff = packet.get('gooseLengthDiff', 0)
    apdu_size_diff = packet.get('apduSizeDiff', 0)
    stnum_diff = packet.get('stDiff', 0)
    if goose_length_diff == 0 and apdu_size_diff == 0 and stnum_diff > 1:
        return True
    return False

def rule_high_StNum_excessive_stnum_jump(packet: dict) -> bool:
    stnum = packet.get('StNum', 0)
    stnum_diff = packet.get('stDiff', 0)
    if stnum_diff > 100:
        return True
    if stnum > 1000 and stnum_diff > 10:
        return True
    return False

def rule_injection_jumps_stnum_time_diff(packet: dict) -> bool:
    stnum = packet.get('StNum', 0)
    stnum_diff = packet.get('stDiff', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return stnum_diff < -1000 and timestamp_diff < -3000

def rule_injection_sqnum_reset_pattern(packet: dict) -> bool:
    sqnum = packet.get('SqNum', 0)
    sqnum_diff = packet.get('sqDiff', 0)
    return sqnum_diff > 10 and sqnum > 100

def rule_injection_elevated_cbstatus_change(packet: dict) -> bool:
    cbstatus = packet.get('cbStatus', 0)
    cbstatus_diff = packet.get('cbStatusDiff', 0)
    return cbstatus_diff > 0.5 and cbstatus > 0.5

def rule_injection_static_payload_size(packet: dict) -> bool:
    goose_length_diff = packet.get('gooseLengthDiff', 0)
    apdu_size_diff = packet.get('apduSizeDiff', 0)
    return goose_length_diff == 0 and apdu_size_diff == 0

def rule_injection_stnum_value_collapse(packet: dict) -> bool:
    stnum = packet.get('StNum', 0)
    stnum_diff = packet.get('stDiff', 0)
    return stnum_diff < -100 and stnum < 100

def rule_inverse_replay_stnum_jump(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    stnum = packet.get('StNum', 0)
    prev_stnum = packet.get('prev_StNum', 0)
    st_diff = packet.get('stDiff', 0)
    return (stnum - prev_stnum) > 5 and st_diff > 5

def rule_inverse_replay_sqnum_decrease(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    sqnum = packet.get('SqNum', 0)
    prev_sqnum = packet.get('prev_SqNum', 0)
    sq_diff = packet.get('sqDiff', 0)
    return (sqnum - prev_sqnum) < 0 and sq_diff < 0

def rule_inverse_replay_timestamp_seq_mismatch(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    st_diff = packet.get('stDiff', 0)
    sq_diff = packet.get('sqDiff', 0)
    return st_diff > 5 and sq_diff < 0

def rule_inverse_replay_ethsrc_stnum_anomaly(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito desse ataque."""
    eth_src = packet.get('ethSrc', '')
    st_diff = packet.get('stDiff', 0)
    return eth_src.startswith('00:11') and st_diff > 5

def rule_masquerade_fake_fault_sqnum_regression_and_low_abs(packet: dict) -> bool:
    """Detecta regressão de SqNum associada a valores absolutos baixos."""
    sq_diff = packet.get('sqDiff', 0)
    sq_num = packet.get('SqNum', 0)
    return sq_diff < -10 and sq_num < 10

def rule_masquerade_fake_fault_stnum_jump_and_timestamp(packet: dict) -> bool:
    """Detecta salto grande em StNum combinado com diferença de timestamp fora do normal."""
    st_diff = packet.get('stDiff', 0)
    ts_diff = packet.get('timestampDiff', 0)
    return st_diff > 5 and ts_diff > 100

def rule_masquerade_fake_fault_cbstatus_elevation_and_stnum_jump(packet: dict) -> bool:
    """Detecta elevação inesperada de cbStatus junto a salto em StNum."""
    cb_status = packet.get('cbStatus', 0)
    st_diff = packet.get('stDiff', 0)
    return cb_status > 0.8 and st_diff > 5

def rule_masquerade_fake_fault_inconsistent_timing_and_sqnum_regression(packet: dict) -> bool:
    """Detecta padrão inconsistente de tempo associado à regressão de SqNum."""
    sq_diff = packet.get('sqDiff', 0)
    st_diff = packet.get('stDiff', 0)
    ts_diff = packet.get('timestampDiff', 0)
    return sq_diff < 0 and st_diff > 5 and ts_diff > 100

def rule_masquerade_fake_fault_src_dst_change_with_counters(packet: dict) -> bool:
    """Detecta mudança de endereços MAC combinada com variação anômala de contadores."""
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    st_diff = packet.get('stDiff', 0)
    sq_diff = packet.get('sqDiff', 0)
    return eth_src != eth_dst and (st_diff > 5 or sq_diff < -10)

def rule_masquerade_fake_normal_jumps_stnum(packet: dict) -> bool:
    stnum = packet.get('StNum', 0)
    stnum_diff = packet.get('stNumDiff', 0)
    return stnum_diff > 500 and stnum > 1000

def rule_masquerade_fake_normal_sqnum_regression(packet: dict) -> bool:
    sqnum = packet.get('SqNum', 0)
    sqnum_diff = packet.get('sqNumDiff', 0)
    return sqnum_diff < -5 and sqnum < 10

def rule_masquerade_fake_normal_time_reversal(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < -10000

def rule_masquerade_fake_normal_stnum_sqnum_mismatch(packet: dict) -> bool:
    stnum = packet.get('StNum', 0)
    sqnum = packet.get('SqNum', 0)
    stnum_diff = packet.get('stNumDiff', 0)
    sqnum_diff = packet.get('sqNumDiff', 0)
    return stnum_diff > 100 and sqnum_diff < 0

def rule_masquerade_fake_normal_negative_sqnum_diff(packet: dict) -> bool:
    sqnum_diff = packet.get('sqNumDiff', 0)
    return sqnum_diff < 0

def rule_poisoned_high_rate_jumps_stnum(packet: dict) -> bool:
    """
    Detect an unusually large increase in StNum.
    Uses the derived field 'stNumDiff' (current StNum - previous StNum).
    """
    stnum_diff = packet.get('stNumDiff', 0)          # difference to previous StNum
    return stnum_diff > 1000

def rule_poisoned_high_rate_sqnum_reset(packet: dict) -> bool:
    """
    Detect a sudden reset or drastic drop of the sequence number.
    Combines current SqNum with the previous value (prev_SqNum).
    """
    sqnum = packet.get('SqNum', 0)
    prev_sqnum = packet.get('prev_SqNum', 0)
    return sqnum < prev_sqnum * 0.1

def rule_poisoned_high_rate_stdiff_regression(packet: dict) -> bool:
    """
    Detect a large negative timestamp regression between status changes.
    Uses the derived field 'stDiff' (time between successive status-change events).
    """
    st_diff = packet.get('stDiff', 0)                # in milliseconds
    return st_diff < -100

def rule_poisoned_high_rate_sqdiff_negative(packet: dict) -> bool:
    """
    Detect a negative interval between consecutive GOOSE frames.
    Uses the derived field 'sqDiff' (time between frames based on SqNum).
    """
    sq_diff = packet.get('sqDiff', 0)                # in milliseconds
    return sq_diff < 0

def rule_poisoned_high_rate_combined(packet: dict) -> bool:
    """
    Strongest indicator: all four anomalous behaviours appear together.
    Combines:
      - Large StNum jump (stNumDiff)
      - SqNum reset (current vs previous)
      - Negative stDiff
      - Negative sqDiff
    """
    stnum_diff = packet.get('stNumDiff', 0)
    sqnum = packet.get('SqNum', 0)
    prev_sqnum = packet.get('prev_SqNum', 0)
    st_diff = packet.get('stDiff', 0)
    sq_diff = packet.get('sqDiff', 0)

