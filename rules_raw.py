# === grayhole ===


def rule_grayhole_low_sqnum_tdiff(packet: dict) -> bool:
    """Detect grayhole: very low SqNum combined with high tDiff."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 5) and (t_diff > 1500)


def rule_grayhole_low_sqnum_stnum(packet: dict) -> bool:
    """Detect grayhole: very low SqNum combined with unusually low StNum."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num < 5) and (st_num < 30)


def rule_grayhole_low_sqnum_sqdiff(packet: dict) -> bool:
    """Detect grayhole: very low SqNum combined with abnormally negative sqDiff."""
    sq_num = packet.get("SqNum", 0)
    sq_diff = packet.get("sqDiff", 0)
    return (sq_num < 5) and (sq_diff < -70)


def rule_grayhole_low_sqnum_stdiff(packet: dict) -> bool:
    """Detect grayhole: very low SqNum combined with unusually high stDiff."""
    sq_num = packet.get("SqNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_num < 5) and (st_diff > 500)


# === high_StNum ===


def rule_high_StNum_stnum_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum com base em StNum e stDiff."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 1000) and (stdiff > 1000)


def rule_high_StNum_time_sqnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum com base em tempo negativo, SqNum e sqDiff."""
    time_last = packet.get("timeFromLastChange", 0)
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    return (time_last < 0) and (sqnum > 70) and (sqdiff > 60)


# === injection ===


def rule_injection_seq_state(packet: dict) -> bool:
    """Detect injection based on abnormal sequence and state numbers."""
    sq_num = packet.get("SqNum", 0)
    sq_diff = packet.get("sqDiff", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 80) and (sq_diff > 50) and (st_num < 30)


def rule_injection_time_status(packet: dict) -> bool:
    """Detect injection based on impossible time values and status field."""
    t_diff = packet.get("tDiff", 0)
    time_last = packet.get("timeFromLastChange", 0)
    cb_status = packet.get("cbStatus", 0)
    return (t_diff < -200) and (time_last < 0) and (cb_status > 2)


# === inverse_replay ===


def rule_inverse_replay_seq_state(packet: dict) -> bool:
    """Detect inverse replay by unusually low sequence and state numbers with backward timestamp."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num <= 0) and (st_num < 20) and (t_diff < -130)


def rule_inverse_replay_state_jump_time(packet: dict) -> bool:
    """Detect inverse replay by excessive state jump, long unchanged interval, and forward timestamp jump."""
    st_diff = packet.get("stDiff", 0)
    time_last_change = packet.get("timeFromLastChange", 0)
    t_diff = packet.get("tDiff", 0)
    return (st_diff > 400) and (time_last_change > 60) and (t_diff > 1500)


# === masquerade_fake_fault ===


def rule_masquerade_fake_fault_tdiff_timestamp(packet: dict) -> bool:
    """Detect elevated tDiff combined with high timestampDiff."""
    t_diff = packet.get("tDiff", 0)
    ts_diff = packet.get("timestampDiff", 0)
    return (t_diff > 1500) and (ts_diff > 0.4)


def rule_masquerade_fake_fault_stdiff_tdiff(packet: dict) -> bool:
    """Detect high stDiff together with elevated tDiff."""
    st_diff = packet.get("stDiff", 0)
    t_diff = packet.get("tDiff", 0)
    return (st_diff > 500) and (t_diff > 1300)


def rule_masquerade_fake_fault_sqnum_timestamp(packet: dict) -> bool:
    """Detect unusually low SqNum with large timestampDiff."""
    sq_num = packet.get("SqNum", 0)
    ts_diff = packet.get("timestampDiff", 0)
    return (sq_num < 0.5) and (ts_diff > 0.5)


def rule_masquerade_fake_fault_stnum_sqdiff(packet: dict) -> bool:
    """Detect low StNum together with excessive sqDiff."""
    st_num = packet.get("StNum", 0)
    sq_diff = packet.get("sqDiff", 0)
    return (st_num < 30) and (sq_diff > 40)


# === masquerade_fake_normal ===


def rule_masquerade_fake_normal_stnum_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 700) and (stdiff > 500)


def rule_masquerade_fake_normal_stnum_sqdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    stnum = packet.get("StNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    return (stnum > 700) and (sqdiff > 50)


# === poisoned_high_rate ===


def rule_poisoned_high_rate_time_anomaly(packet: dict) -> bool:
    """Retorna True se o pacote apresentar anomalias de tempo típicas de poisoned_high_rate."""
    tDiff = packet.get("tDiff", 0)
    timestampDiff = packet.get("timestampDiff", 0)
    StNum = packet.get("StNum", 0)
    return (tDiff < -200) and (timestampDiff > 0.5) and (StNum > 700)


def rule_poisoned_high_rate_stale_data(packet: dict) -> bool:
    """Retorna True se o pacote indicar retransmissão de dados antigos com atraso elevado."""
    timeFromLastChange = packet.get("timeFromLastChange", 0)
    delay = packet.get("delay", 0)
    sqDiff = packet.get("sqDiff", 0)
    return (timeFromLastChange > 60) and (delay > 0.001) and (sqDiff < -70)


# === random_replay ===


def rule_random_replay_a(packet: dict) -> bool:
    """Detect random replay: very low stDiff combined with high sqDiff."""
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return (st_diff < -65000) and (sq_diff > 35)


def rule_random_replay_b(packet: dict) -> bool:
    """Detect random replay: unusually high SqNum together with abnormally low StNum."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 55) and (st_num < 30)


def rule_random_replay_c(packet: dict) -> bool:
    """Detect random replay: large timestamp jitter and prolonged inter‑event interval."""
    ts_diff = packet.get("timestampDiff", 0)
    time_last_change = packet.get("timeFromLastChange", 0)
    return (ts_diff > 0.5) and (time_last_change > 60)


def rule_random_replay_d(packet: dict) -> bool:
    """Detect random replay: extreme tDiff together with very negative stDiff."""
    t_diff = packet.get("tDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return (t_diff > 1500) and (st_diff < -65000)
