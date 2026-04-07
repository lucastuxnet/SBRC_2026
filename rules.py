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


## high_StNum        return True
    return False



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


## grayhole


def rule_grayhole_stnum_zero(packet: dict) -> bool:
    """Detect grayhole attack when StNum is zero."""
    return packet.get('StNum') == 0.0

def rule_grayhole_sqdiff_zero(packet: dict) -> bool:
    """Detect grayhole attack when sqDiff is zero."""
    return packet.get('sqDiff') == 0.0

def rule_grayhole_timestampdiff_zero(packet: dict) -> bool:
    """Detect grayhole attack when timestampDiff is zero."""
    return packet.get('timestampDiff') == 0.0

def rule_grayhole_combined(packet: dict) -> bool:
    """Detect grayhole attack when StNum, sqDiff and timestampDiff are all zero."""
    return (packet.get('StNum') == 0.0 and
            packet.get('sqDiff') == 0.0 and
            packet.get('timestampDiff') == 0.0)

def rule_grayhole_suspicious_sqnum(packet: dict) -> bool:
    """Detect grayhole attack when SqNum is unusually high while other fields are zero."""
    return (packet.get('SqNum', 0) > 10.0 and
            packet.get('StNum') == 0.0 and
            packet.get('sqDiff') == 0.0)

def rule_grayhole_tdiff_nonzero(packet: dict) -> bool:
    """Detect grayhole attack when tDiff is non‑zero but other indicators are zero."""
    return (packet.get('tDiff') != 0.0 and
            packet.get('StNum') == 0.0 and
            packet.get('sqDiff') == 0.0)


# === grayhole ===


def rule_grayhole_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    prev_st_num = packet.get('prev_st_num', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (sq_num == prev_sq_num and st_num == prev_st_num and timestamp_diff == prev_timestamp_diff)

def rule_grayhole_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prev_st_num', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (st_num > prev_st_num and timestamp_diff < prev_timestamp_diff)

def rule_grayhole_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    prev_st_num = packet.get('prev_st_num', 0)

    return (sq_num < prev_sq_num and st_num < prev_st_num)

def rule_grayhole_anomalous_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (timestamp_diff < prev_timestamp_diff * 0.8 or timestamp_diff > prev_timestamp_diff * 1.2)

def rule_grayhole_falsification_state(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    prev_cb_status = packet.get('prev_cb_status', 0)
    prev_go_id = packet.get('prev_go_id', 0)

    return (cb_status != prev_cb_status or go_id != prev_go_id)

def rule_grayhole_injection_forged_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    prev_st_num = packet.get('prev_st_num', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (sq_num != prev_sq_num + 1 or st_num != prev_st_num + 1 or timestamp_diff != prev_timestamp_diff)

def rule_grayhole_reset_sequence(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    prev_st_num = packet.get('prev_st_num', 0)

    return (sq_num < prev_sq_num or st_num < prev_st_num)

def rule_grayhole_different_origins(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    prev_eth_src = packet.get('prev_eth_src', '')
    prev_eth_dst = packet.get('prev_eth_dst', '')

    return (eth_src != prev_eth_src or eth_dst != prev_eth_dst)

def rule_grayhole_different_destinations(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    prev_eth_src = packet.get('prev_eth_src', '')
    prev_eth_dst = packet.get('prev_eth_dst', '')

    return (eth_src != prev_eth_src or eth_dst != prev_eth_dst)


# === high_StNum ===


def rule_high_StNum_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 10 and (st_num - prev_st_num) > 10 and (timestamp_diff - prev_timestamp_diff) > 1000

def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (st_num - prev_st_num) > 10 and (timestamp_diff - prev_timestamp_diff) < 100

def rule_high_StNum_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    prev_cb_status = packet.get('prev_cbStatus', 0)
    prev_go_id = packet.get('prev_goID', 0)

    return cb_status != prev_cb_status or go_id != prev_go_id

def rule_high_StNum_injection(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 10 and (st_num - prev_st_num) > 10 and (timestamp_diff - prev_timestamp_diff) > 1000

def rule_high_StNum_anomalies_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return abs(timestamp_diff - prev_timestamp_diff) > 500


# === injection ===


def rule_injection_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (st_num > 10 and timestamp_diff < 100) or (st_num < 5 and timestamp_diff > 500)

def rule_injection_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num > st_num + 5 or sq_num < st_num - 5

def rule_injection_cbstatus_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    st_num = packet.get('StNum', 0)
    return cb_status != st_num % 2

def rule_injection_timestamp_diff_anomaly(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 50 or timestamp_diff > 1000

def rule_injection_ethsrc_falsification(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    st_num = packet.get('StNum', 0)
    return eth_src != '00:11:22:33:44:55' or st_num % 2 != 0

def rule_injection_ethdst_falsification(packet: dict) -> bool:
    eth_dst = packet.get('ethDst', '')
    sq_num = packet.get('SqNum', 0)
    return eth_dst != '00:11:22:33:44:66' or sq_num % 3 != 0


# === grayhole ===


def rule_grayhole_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num - st_num) > 10 and timestamp_diff < 100

def rule_grayhole_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return abs(st_num - sq_num) > 5 and timestamp_diff < 50

def rule_grayhole_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    return cb_status != 0 and go_id != 0

def rule_grayhole_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return eth_src != eth_dst

def rule_grayhole_anomalous_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    return timestamp_diff < 20 or timestamp_diff > 200

def rule_grayhole_reset_sequence(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_irregular_intervals(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 10 or timestamp_diff > 500


# === high_StNum ===


def rule_high_StNum_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 1 and (st_num - prev_st_num) > 1 and timestamp_diff < 100

def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (st_num - prev_st_num) > 10 and timestamp_diff < 100

def rule_high_StNum_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)

    return sq_num == 0 and st_num == 0 and (sq_num - prev_sq_num) > 1 and (st_num - prev_st_num) > 1

def rule_high_StNum_falsification_state(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)

    return cb_status == 0 and go_id > 1000

def rule_high_StNum_injection_forged_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 100 and (st_num - prev_st_num) > 100 and timestamp_diff < 100


# === injection ===


def rule_injection_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    cb_status = packet.get('cbStatus', 0)
    
    st_num_diff = st_num - packet.get('prev_st_num', 0)
    sq_num_diff = sq_num - packet.get('prev_sq_num', 0)
    
    return (st_num_diff > 2 and timestamp_diff < 100) or (sq_num_diff > 2 and timestamp_diff < 100)

def rule_injection_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    
    return sq_num == prev_sq_num

def rule_injection_freq_anomalous(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)
    
    return abs(timestamp_diff - prev_timestamp_diff) > 200

def rule_injection_ethsrc_ethdst_outside_topology(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    
    return eth_src not in ['10.0.0.1', '10.0.0.2'] or eth_dst not in ['10.0.0.3', '10.0.0.4']

def rule_injection_cbstatus_diff_outside_expected(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    prev_cb_status = packet.get('prev_cb_status', 0)
    
    return abs(cb_status - prev_cb_status) > 2


# === grayhole ===


def rule_grayhole_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num - st_num) > 10 and timestamp_diff < 100

def rule_grayhole_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return abs(st_num - sq_num) > 5 and timestamp_diff < 50

def rule_grayhole_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    return cb_status != 0 and go_id != 0

def rule_grayhole_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return eth_src != eth_dst

def rule_grayhole_anomalous_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    return timestamp_diff < 20 or timestamp_diff > 200

def rule_grayhole_reset_sequence(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_irregular_intervals(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 10 or timestamp_diff > 500


# === high_StNum ===


def rule_high_StNum_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 1 and (st_num - prev_st_num) > 1 and timestamp_diff < 100

def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (st_num - prev_st_num) > 10 and (timestamp_diff - prev_timestamp_diff) < 100

def rule_high_StNum_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)

    return (sq_num == 0 and st_num == 0) or (sq_num == prev_sq_num and st_num == prev_st_num)

def rule_high_StNum_falsification_state(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)

    return cb_status == 0 and go_id > 1000

def rule_high_StNum_injection_forged_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 100 and (st_num - prev_st_num) > 100 and timestamp_diff < 100


# === injection ===


def rule_injection_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    cb_status = packet.get('cbStatus', 0)
    
    st_num_diff = st_num - packet.get('prev_st_num', 0)
    sq_num_diff = sq_num - packet.get('prev_sq_num', 0)
    
    return (st_num_diff > 2 and timestamp_diff < 100) or (sq_num_diff > 2 and timestamp_diff < 100)

def rule_injection_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    
    return sq_num == prev_sq_num

def rule_injection_freq_anomalous(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)
    
    return abs(timestamp_diff - prev_timestamp_diff) > 500

def rule_injection_ethsrc_ethdst_outside_topology(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    
    return eth_src not in ['10.0.0.1', '10.0.0.2'] or eth_dst not in ['10.0.0.3', '10.0.0.4']

def rule_injection_cbstatus_diff_outside_expected(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    prev_cb_status = packet.get('prev_cb_status', 0)
    
    return abs(cb_status - prev_cb_status) > 2


# === inverse_replay ===


def rule_inverse_replay_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num > 1 and st_num > 1 and timestamp_diff < 100) or (sq_num > 1 and st_num == 1 and timestamp_diff < 100)

def rule_inverse_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (st_num > 1 and timestamp_diff < 100 and sq_num > st_num)

def rule_inverse_replay_cb_status_diff(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    cb_status_diff = packet.get('cbStatusDiff', 0)
    return cb_status_diff != 0 and cb_status != 0

def rule_inverse_replay_eth_src_dst(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return eth_src != '10.0.0.1' or eth_dst != '10.0.0.2'

def rule_inverse_replay_anomalous_frequency(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 50 and sq_num > 10

def rule_inverse_replay_flood_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 10 and sq_num > 10


# === masquerade_fake_fault ===


def rule_masquerade_fake_fault_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num > st_num) or (st_num > sq_num + 10) or (timestamp_diff > 1000)

def rule_masquerade_fake_fault_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (abs(sq_num - st_num) > 10) and (timestamp_diff > 1000)

def rule_masquerade_fake_fault_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return (sq_num == 0) and (st_num > 10)

def rule_masquerade_fake_fault_cbstatus_goID_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    return (cb_status != 0) and (go_id != 0)

def rule_masquerade_fake_fault_ethsrc_ethdst_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return (eth_src != eth_dst) and (len(eth_src) > 10) and (len(eth_dst) > 10)


# === masquerade_fake_normal ===


def rule_masquerade_fake_normal_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num == 1 and st_num - prev_st_num == 1 and
            timestamp_diff - prev_timestamp_diff < 1000)  # 1 segundo

def rule_masquerade_fake_normal_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    return cb_status == 0

def rule_masquerade_fake_normal_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    st_num = packet.get('StNum', 0)
    sq_num = packet.get('SqNum', 0)

    return (eth_src != packet.get('prevEthSrc', '') or
            eth_dst != packet.get('prevEthDst', '') or
            st_num - packet.get('prevStNum', 0) > 10 or
            sq_num - packet.get('prevSqNum', 0) > 10)

def rule_masquerade_fake_normal_anomaly(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 100  # frequência anômala

def rule_masquerade_fake_normal_reset(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)

    return (sq_num == 0 and st_num == 0 and
            prev_sq_num > 0 and prev_st_num > 0)


# === poisoned_high_rate ===


def rule_poisoned_high_rate_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num == prev_sq_num and st_num == prev_st_num and timestamp_diff > 2 * prev_timestamp_diff) or \
           (sq_num != prev_sq_num and st_num != prev_st_num and timestamp_diff < 2 * prev_timestamp_diff)


def rule_poisoned_high_rate_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num > 10 and st_num - prev_st_num > 10 and timestamp_diff < 2 * prev_timestamp_diff) or \
           (sq_num - prev_sq_num < -10 and st_num - prev_st_num < -10 and timestamp_diff > 2 * prev_timestamp_diff)


def rule_poisoned_high_rate_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num == 0 and st_num == 0 and timestamp_diff > 2 * prev_timestamp_diff) or \
           (sq_num != 0 and st_num != 0 and timestamp_diff < 2 * prev_timestamp_diff)


def rule_poisoned_high_rate_falsification_state(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', '')

    return cb_status == 1 and go_id == "IntLockA"


def rule_poisoned_high_rate_injection_forged_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num > 2 * prev_sq_num and st_num > 2 * prev_st_num and timestamp_diff > 2 * prev_timestamp_diff) or \
           (sq_num < 2 * prev_sq_num and st_num < 2 * prev_st_num and timestamp_diff < 2 * prev_timestamp_diff)


# === random_replay ===


def rule_random_replay_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num) != (st_num - prev_st_num) or \
           abs(timestamp_diff - prev_timestamp_diff) > 1000 or \
           timestamp_diff < 100

def rule_random_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return abs(st_num - prev_st_num) > 10 and \
           abs(sq_num - prev_sq_num) > 10 and \
           abs(timestamp_diff - prev_timestamp_diff) > 1000

def rule_random_replay_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return sq_num == prev_sq_num and \
           st_num == prev_st_num and \
           timestamp_diff < 1000

def rule_random_replay_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    prev_cb_status = packet.get('prevCbStatus', 0)
    prev_go_id = packet.get('prevGoID', 0)

    return cb_status != prev_cb_status or \
           go_id != prev_go_id

def rule_random_replay_flood(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return abs(st_num - prev_st_num) > 100 and \
           abs(sq_num - prev_sq_num) > 100 and \
           abs(timestamp_diff - prev_timestamp_diff) < 100


# === grayhole ===


def rule_grayhole_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num - st_num) > 10 and timestamp_diff < 100

def rule_grayhole_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return abs(st_num - sq_num) > 5 and timestamp_diff < 50

def rule_grayhole_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    return cb_status != 0 and go_id != 0

def rule_grayhole_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return eth_src != eth_dst

def rule_grayhole_anomalous_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    return timestamp_diff < 20 or timestamp_diff > 200

def rule_grayhole_reset_sequence(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_irregular_intervals(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 10 or timestamp_diff > 500


# === grayhole ===


def rule_grayhole_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num - st_num) > 10 and timestamp_diff < 100

def rule_grayhole_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return abs(st_num - sq_num) > 5 and timestamp_diff < 50

def rule_grayhole_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    return cb_status != 0 and go_id != 0

def rule_grayhole_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return eth_src != eth_dst

def rule_grayhole_anomalous_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    return timestamp_diff < 20 or timestamp_diff > 200

def rule_grayhole_reset_sequence(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num == 0 and st_num == 0

def rule_grayhole_irregular_intervals(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 10 or timestamp_diff > 500


# === high_StNum ===


def rule_high_StNum_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 1 and (st_num - prev_st_num) > 1 and timestamp_diff < 100

def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (st_num - prev_st_num) > 10 and timestamp_diff < 100

def rule_high_StNum_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)

    return sq_num == 0 and st_num == 0 and (sq_num - prev_sq_num) > 1 and (st_num - prev_st_num) > 1

def rule_high_StNum_falsification_state(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)

    return cb_status == 0 and go_id > 1000

def rule_high_StNum_injection_forged_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)

    return (sq_num - prev_sq_num) > 100 and (st_num - prev_st_num) > 100 and timestamp_diff < 100


# === injection ===


def rule_injection_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    cb_status = packet.get('cbStatus', 0)
    
    st_num_diff = st_num - packet.get('prev_st_num', 0)
    sq_num_diff = sq_num - packet.get('prev_sq_num', 0)
    
    return (st_num_diff > 2 and timestamp_diff < 100) or (sq_num_diff > 2 and timestamp_diff < 100)

def rule_injection_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    
    return sq_num == prev_sq_num

def rule_injection_freq_anomalous(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)
    
    return abs(timestamp_diff - prev_timestamp_diff) > 500

def rule_injection_ethsrc_ethdst_outside_topology(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    
    return eth_src not in ['10.0.0.1', '10.0.0.2'] or eth_dst not in ['10.0.0.3', '10.0.0.4']

def rule_injection_cbstatus_diff_outside_expected(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    prev_cb_status = packet.get('prev_cb_status', 0)
    
    return abs(cb_status - prev_cb_status) > 2


# === inverse_replay ===


def rule_inverse_replay_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num > 1 and st_num > 1 and timestamp_diff < 100) or (sq_num > 1 and st_num == 1 and timestamp_diff < 100)

def rule_inverse_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (st_num > 1 and timestamp_diff < 100 and sq_num > st_num)

def rule_inverse_replay_cb_status_diff(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    cb_status_diff = packet.get('cbStatusDiff', 0)
    return cb_status_diff != 0 and cb_status != 0

def rule_inverse_replay_eth_src_dst(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return eth_src != '10.0.0.1' or eth_dst != '10.0.0.2'

def rule_inverse_replay_anomalous_frequency(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 50 and sq_num > 10

def rule_inverse_replay_flood_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 10 and sq_num > 10


# === masquerade_fake_fault ===


def rule_masquerade_fake_fault_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (sq_num > st_num) or (st_num > sq_num + 10) or (timestamp_diff > 1000)

def rule_masquerade_fake_fault_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return (abs(sq_num - st_num) > 10) and (timestamp_diff > 1000)

def rule_masquerade_fake_fault_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return (sq_num == 0) and (st_num > 10)

def rule_masquerade_fake_fault_cbstatus_goID_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    return (cb_status != 0) and (go_id != 0)

def rule_masquerade_fake_fault_ethsrc_ethdst_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    return (eth_src != eth_dst) and (len(eth_src) > 10) and (len(eth_dst) > 10)


# === masquerade_fake_normal ===


def rule_masquerade_fake_normal_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num == 1 and st_num - prev_st_num == 1 and
            timestamp_diff - prev_timestamp_diff < 1000)  # 1 segundo

def rule_masquerade_fake_normal_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    return cb_status == 0

def rule_masquerade_fake_normal_injection(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    st_num = packet.get('StNum', 0)
    sq_num = packet.get('SqNum', 0)

    return (eth_src != packet.get('prevEthSrc', '') or
            eth_dst != packet.get('prevEthDst', '') or
            st_num - packet.get('prevStNum', 0) > 10 or
            sq_num - packet.get('prevSqNum', 0) > 10)

def rule_masquerade_fake_normal_anomaly(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    return timestamp_diff < 100  # frequência anômala

def rule_masquerade_fake_normal_reset(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)

    return (sq_num == 0 and st_num == 0 and
            prev_sq_num > 0 and prev_st_num > 0)


# === poisoned_high_rate ===


def rule_poisoned_high_rate_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num == prev_sq_num and st_num == prev_st_num and timestamp_diff > 2 * prev_timestamp_diff) or \
           (sq_num != prev_sq_num and st_num != prev_st_num and timestamp_diff < 2 * prev_timestamp_diff)


def rule_poisoned_high_rate_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num > 10 and st_num - prev_st_num > 10 and timestamp_diff < 2 * prev_timestamp_diff) or \
           (sq_num - prev_sq_num < -10 and st_num - prev_st_num < -10 and timestamp_diff > 2 * prev_timestamp_diff)


def rule_poisoned_high_rate_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num == 0 and st_num == 0 and timestamp_diff > 2 * prev_timestamp_diff) or \
           (sq_num != 0 and st_num != 0 and timestamp_diff < 2 * prev_timestamp_diff)


def rule_poisoned_high_rate_falsification_state(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', '')

    return cb_status == 1 and go_id == "IntLockA"


def rule_poisoned_high_rate_injection_forged_packets(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num > 2 * prev_sq_num and st_num > 2 * prev_st_num and timestamp_diff > 2 * prev_timestamp_diff) or \
           (sq_num < 2 * prev_sq_num and st_num < 2 * prev_st_num and timestamp_diff < 2 * prev_timestamp_diff)


# === random_replay ===


def rule_random_replay_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num) != (st_num - prev_st_num) or \
           abs(timestamp_diff - prev_timestamp_diff) > 1000 or \
           timestamp_diff < 100

def rule_random_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return abs(st_num - prev_st_num) > 10 or \
           abs(sq_num - prev_sq_num) > 10 or \
           abs(timestamp_diff - prev_timestamp_diff) > 1000

def rule_random_replay_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num == 0 and st_num > 0) or \
           (sq_num > 0 and st_num == 0) or \
           (sq_num == prev_sq_num and st_num != prev_st_num)

def rule_random_replay_falsification_state(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    prev_cb_status = packet.get('prevCbStatus', 0)
    prev_go_id = packet.get('prevGoID', 0)

    return cb_status != prev_cb_status or go_id != prev_go_id

def rule_random_replay_flood(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return timestamp_diff < 100 and \
           abs(st_num - prev_st_num) > 10 and \
           abs(sq_num - prev_sq_num) > 10


# === grayhole ===


def rule_grayhole_jumps_stnum_time_diff(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', 0)
    stNum = packet.get('StNum', 0)
    return timestampDiff < 10 and stNum > 100 and stNum % 10 == 0

def rule_grayhole_sqnum_reset_pattern(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    return sqNum > stNum and sqNum - stNum > 10 and sqNum % 10 == 0

def rule_grayhole_cbstatus_falsification(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', 0)
    return cbStatus != 0 and cbStatus != 1 and cbStatus != 2

def rule_grayhole_goose_length_diff_injection(packet: dict) -> bool:
    gooseLengthDiff = packet.get('gooseLengthDiff', 0)
    apduSizeDiff = packet.get('apduSizeDiff', 0)
    return gooseLengthDiff != 0 and apduSizeDiff != 0 and gooseLengthDiff > 10 and apduSizeDiff > 10

def rule_grayhole_frame_length_diff_injection(packet: dict) -> bool:
    frameLengthDiff = packet.get('frameLengthDiff', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return frameLengthDiff != 0 and timestampDiff != 0 and frameLengthDiff > 10 and timestampDiff > 10

def rule_grayhole_delay_replay(packet: dict) -> bool:
    delay = packet.get('delay', 0)
    return delay < 10 and delay > 0

def rule_grayhole_timefromlastchange_replay(packet: dict) -> bool:
    timeFromLastChange = packet.get('timeFromLastChange', 0)
    return timeFromLastChange < 10 and timeFromLastChange > 0

def rule_grayhole_tdif_replay(packet: dict) -> bool:
    tDiff = packet.get('tDiff', 0)
    return tDiff < 10 and tDiff > 0

def rule_grayhole_sqnum_stnum_change_sense(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    return sqNum > stNum and sqNum - stNum > 10 and sqNum % 10 == 0 and stNum % 10 == 0

def rule_grayhole_cbstatus_change_sense(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', 0)
    return cbStatus != 0 and cbStatus != 1 and cbStatus != 2 and cbStatus % 2 == 0

def rule_grayhole_goose_length_diff_change_sense(packet: dict) -> bool:
    gooseLengthDiff = packet.get('gooseLengthDiff', 0)
    apduSizeDiff = packet.get('apduSizeDiff', 0)
    return gooseLengthDiff != 0 and apduSizeDiff != 0 and gooseLengthDiff > 10 and apduSizeDiff > 10 and gooseLengthDiff % 2 == 0 and apduSizeDiff % 2 == 0

def rule_grayhole_frame_length_diff_change_sense(packet: dict) -> bool:
    frameLengthDiff = packet.get('frameLengthDiff', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return frameLengthDiff != 0 and timestampDiff != 0 and frameLengthDiff > 10 and timestampDiff > 10 and frameLengthDiff % 2 == 0 and timestampDiff % 2 == 0

def rule_grayhole_delay_change_sense(packet: dict) -> bool:
    delay = packet.get('delay', 0)
    return delay < 10 and delay > 0 and delay % 2 == 0

def rule_grayhole_timefromlastchange_change_sense(packet: dict) -> bool:
    timeFromLastChange = packet.get('timeFromLastChange', 0)
    return timeFromLastChange < 10 and timeFromLastChange > 0 and timeFromLastChange % 2 == 0

def rule_grayhole_tdif_change_sense(packet: dict) -> bool:
    tDiff = packet.get('tDiff', 0)
    return tDiff < 10 and tDiff > 0 and tDiff % 2 == 0

def rule_grayhole_sqnum_stnum_change_sense_sequence(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    return sqNum > stNum and sqNum - stNum > 10 and sqNum % 10 == 0 and stNum % 10 == 0 and sqNum > stNum + 10 and sqNum % 10 == 0 and stNum % 10 == 0

def rule_grayhole_cbstatus_change_sense_sequence(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', 0)
    return cbStatus != 0 and cbStatus != 1 and cbStatus != 2 and cbStatus % 2 == 0 and cbStatus != 0 and cbStatus != 1 and cbStatus != 2 and cbStatus % 2 == 0

def rule_grayhole_goose_length_diff_change_sense_sequence(packet: dict) -> bool:
    gooseLengthDiff = packet.get('gooseLengthDiff', 0)
    apduSizeDiff = packet.get('apduSizeDiff', 0)
    return gooseLengthDiff != 0 and apduSizeDiff != 0 and gooseLengthDiff > 10 and apduSizeDiff > 10 and gooseLengthDiff % 2 == 0 and apduSizeDiff % 2 == 0 and gooseLengthDiff != 0 and apduSizeDiff != 0 and gooseLengthDiff > 10 and apduSizeDiff > 10 and gooseLengthDiff % 2 == 0 and apduSizeDiff % 2 == 0

def rule_grayhole_frame_length_diff_change_sense_sequence(packet: dict) -> bool:
    frameLengthDiff = packet.get('frameLengthDiff', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return frameLengthDiff != 0 and timestampDiff != 0 and frameLengthDiff > 10 and timestampDiff > 10 and frameLengthDiff % 2 == 0 and timestampDiff % 2 == 0 and frameLengthDiff != 0 and timestampDiff != 0 and frameLengthDiff > 10 and timestampDiff > 10 and frameLengthDiff % 2 == 0 and timestampDiff % 2 == 0

def rule_grayhole_delay_change_sense_sequence(packet: dict) -> bool:
    delay = packet.get('delay', 0)
    return delay < 10 and delay > 0 and delay % 2 == 0 and delay != 0 and delay > 0 and delay % 2 == 0

def rule_grayhole_timefromlastchange_change_sense_sequence(packet: dict) -> bool:
    timeFromLastChange = packet.get('timeFromLastChange', 0)
    return timeFromLastChange < 10 and timeFromLastChange > 0 and timeFromLastChange % 2 == 0 and timeFromLastChange != 0 and timeFromLastChange > 0 and timeFromLastChange % 2 == 0

def rule_grayhole_tdif_change_sense_sequence(packet: dict) -> bool:
    tDiff = packet.get('tDiff', 0)
    return tDiff < 10 and tDiff > 0 and tDiff % 2 == 0 and tDiff != 0 and tDiff > 0 and tDiff % 2 == 0


# === high_StNum ===


def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    stNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    sqDiff = packet.get('sqDiff', 0)
    prev_StNum = packet.get('prev_StNum', 0)

    return (stNum - prev_StNum) > 10 and timestampDiff < 100 and sqDiff < 10

def rule_high_StNum_sqnum_reset_pattern(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    cbStatus = packet.get('cbStatus', 0)

    return (sqNum == 0 and stNum > 1000 and timestampDiff < 100) or (cbStatus != 0 and cbStatus != 1)

def rule_high_StNum_flood_pattern(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', 0)
    prev_timestampDiff = packet.get('prev_timestampDiff', 0)

    return timestampDiff < 10 and prev_timestampDiff > 100

def rule_high_StNum_masquerade_pattern(packet: dict) -> bool:
    ethSrc = packet.get('ethSrc', '')
    ethDst = packet.get('ethDst', '')
    cbStatus = packet.get('cbStatus', 0)

    return (ethSrc != '' and ethDst != '' and cbStatus != 0 and cbStatus != 1)

def rule_high_StNum_replay_pattern(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    prev_sqNum = packet.get('prev_sqNum', 0)
    prev_stNum = packet.get('prev_stNum', 0)
    prev_timestampDiff = packet.get('prev_timestampDiff', 0)

    return (sqNum == prev_sqNum and stNum == prev_stNum and timestampDiff == prev_timestampDiff)


# === injection ===


def rule_injection_cb_status_alterado(packet: dict) -> bool:
    cb_status = packet.get('cbStatus')
    go_id = packet.get('goID')
    return cb_status != packet.get('prev_cbStatus', cb_status) and go_id != packet.get('prev_goID', go_id)

def rule_injection_intervalos_entre_mensagens_anomais(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff')
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)
    return abs(timestamp_diff - prev_timestamp_diff) > 1000  # 1 segundo

def rule_injection_eth_src_dst_anomais(packet: dict) -> bool:
    eth_src = packet.get('ethSrc')
    eth_dst = packet.get('ethDst')
    return eth_src != packet.get('prev_ethSrc', eth_src) or eth_dst != packet.get('prev_ethDst', eth_dst)

def rule_injection_st_num_e_sq_num_fora_de_ordem(packet: dict) -> bool:
    st_num = packet.get('StNum')
    sq_num = packet.get('SqNum')
    prev_st_num = packet.get('prev_StNum', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    return st_num < prev_st_num or sq_num < prev_sq_num

def rule_injection_incrementos_anomais_em_sequencia(packet: dict) -> bool:
    st_num = packet.get('StNum')
    sq_num = packet.get('SqNum')
    prev_st_num = packet.get('prev_StNum', 0)
    prev_sq_num = packet.get('prev_SqNum', 0)
    return abs(st_num - prev_st_num) > 10 or abs(sq_num - prev_sq_num) > 10

def rule_injection_alternancia_entre_valores_normais_e_anomais(packet: dict) -> bool:
    cb_status = packet.get('cbStatus')
    go_id = packet.get('goID')
    prev_cb_status = packet.get('prev_cbStatus', cb_status)
    prev_go_id = packet.get('prev_goID', go_id)
    return cb_status != prev_cb_status or go_id != prev_go_id

def rule_injection_frequencia_irregular_de_mensagens(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff')
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)
    return abs(timestamp_diff - prev_timestamp_diff) > 5000  # 5 segundos

def rule_injection_st_num_alto_sq_diff_baixo_timestamp_diff_pequeno(packet: dict) -> bool:
    st_num = packet.get('StNum')
    sq_diff = packet.get('sqDiff')
    timestamp_diff = packet.get('timestampDiff')
    return st_num > 100 and sq_diff < 10 and timestamp_diff < 1000  # 1 segundo

def rule_injection_cb_status_alterado_go_id_alterado_delay_anomalo(packet: dict) -> bool:
    cb_status = packet.get('cbStatus')
    go_id = packet.get('goID')
    delay = packet.get('delay')
    return cb_status != packet.get('prev_cbStatus', cb_status) and go_id != packet.get('prev_goID', go_id) and delay > 1000  # 1 segundo

def rule_injection_desvio_significativo_em_relacao_a_media_mediana_do_trafego_normal(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff')
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)
    return abs(timestamp_diff - prev_timestamp_diff) > 20000  # 20 segundos

def rule_injection_valores_que_nunca_aparecem_no_trafego_normal(packet: dict) -> bool:
    cb_status = packet.get('cbStatus')
    go_id = packet.get('goID')
    return cb_status not in [packet.get('prev_cbStatus', cb_status), packet.get('prev_prev_cbStatus', cb_status)] or go_id not in [packet.get('prev_goID', go_id), packet.get('prev_prev_goID', go_id)]

def rule_injection_inconsistencias_entre_campos_derivados(packet: dict) -> bool:
    st_num = packet.get('StNum')
    sq_num = packet.get('SqNum')
    st_num_diff = packet.get('stNumDiff')
    sq_num_diff = packet.get('sqNumDiff')
    return st_num_diff != sq_num_diff

def rule_injection_replay_exata_de_pacotes_antigos(packet: dict) -> bool:
    sq_num = packet.get('SqNum')
    st_num = packet.get('StNum')
    timestamp_diff = packet.get('timestampDiff')
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)
    return sq_num == prev_sq_num and st_num == prev_st_num and timestamp_diff == prev_timestamp_diff

def rule_injection_rajada_de_pacotes_em_intervalo_muito_curto(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff')
    prev_timestamp_diff = packet.get('prev_timestampDiff', 0)
    return timestamp_diff < 100  # 0,1 segundos

def rule_injection_falsificacao_consistente_de_eth_src_dst_cb_status(packet: dict) -> bool:
    eth_src = packet.get('ethSrc')
    eth_dst = packet.get('ethDst')
    cb_status = packet.get('cbStatus')
    return eth_src != packet.get('prev_ethSrc', eth_src) or eth_dst != packet.get('prev_ethDst', eth_dst) or cb_status != packet.get('prev_cbStatus', cb_status)

def rule_injection_pacotes_que_desaparecem_e_reaparecem_com_numeros_de_sequencia_fora_de_ordem(packet: dict) -> bool:
    sq_num = packet.get('SqNum')
    st_num = packet.get('StNum')
    prev_sq_num = packet.get('prev_SqNum', 0)
    prev_st_num = packet.get('prev_StNum', 0)
    return sq_num < prev_sq_num or st_num < prev_st_num


# === inverse_replay ===


def rule_inverse_replay_sqnum_reset_pattern(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return (sqNum == 0 and stNum > 0 and timestampDiff > 0) or (sqNum > 0 and stNum == 0 and timestampDiff < 0)

def rule_inverse_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    stNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    prev_StNum = packet.get('prev_StNum', 0)
    return abs(stNum - prev_StNum) > 10 and abs(timestampDiff) > 100

def rule_inverse_replay_frequencia_irregular_mudanca_estado(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return abs(cbStatus) > 10 and abs(timestampDiff) > 100

def rule_inverse_replay_padrao_alternancia(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    prev_sqNum = packet.get('prev_sqNum', 0)
    prev_stNum = packet.get('prev_stNum', 0)
    prev_timestampDiff = packet.get('prev_timestampDiff', 0)
    return (sqNum > prev_sqNum and stNum < prev_stNum and timestampDiff > prev_timestampDiff) or (sqNum < prev_sqNum and stNum > prev_stNum and timestampDiff < prev_timestampDiff)

def rule_inverse_replay_desvio_significativo(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', 0)
    return abs(timestampDiff) > 1000

def rule_inverse_replay_inconsistencias_campos_derivados(packet: dict) -> bool:
    stDiff = packet.get('stDiff', 0)
    StNum = packet.get('StNum', 0)
    prev_StNum = packet.get('prev_StNum', 0)
    return stDiff != StNum - prev_StNum

def rule_inverse_replay_frequencia_irregular_mudanca_estado_disjuntor(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return abs(cbStatus) > 10 and abs(timestampDiff) > 100

def rule_inverse_replay_pacotes_timestamp_diff_pequeno(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', 0)
    return timestampDiff < 10

def rule_inverse_replay_mudanca_anomala_gooselengthdiff_apdusize(packet: dict) -> bool:
    gooseLengthDiff = packet.get('gooseLengthDiff', 0)
    apduSizeDiff = packet.get('apduSizeDiff', 0)
    return abs(gooseLengthDiff) > 100 and abs(apduSizeDiff) > 100

def rule_inverse_replay_pacotes_frame_length_diff_grande(packet: dict) -> bool:
    frameLengthDiff = packet.get('frameLengthDiff', 0)
    return frameLengthDiff > 1000

def rule_inverse_replay_frequencia_irregular_mudanca_delay(packet: dict) -> bool:
    delay = packet.get('delay', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return abs(delay) > 10 and abs(timestampDiff) > 100

def rule_inverse_replay_pacotes_tdiff_grande(packet: dict) -> bool:
    tDiff = packet.get('tDiff', 0)
    return tDiff > 1000


# === masquerade_fake_fault ===


def rule_masquerade_fake_fault_falsification(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', None)
    ethSrc = packet.get('ethSrc', None)
    ethDst = packet.get('ethDst', None)
    return cbStatus is not None and ethSrc is not None and ethDst is not None and cbStatus != ethSrc and cbStatus != ethDst

def rule_masquerade_fake_fault_flood(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', None)
    return timestampDiff is not None and timestampDiff < 0.1

def rule_masquerade_fake_fault_jumps_stnum_time_diff(packet: dict) -> bool:
    StNum = packet.get('StNum', None)
    timestampDiff = packet.get('timestampDiff', None)
    return StNum is not None and timestampDiff is not None and abs(timestampDiff) > 0.5

def rule_masquerade_fake_fault_sqnum_reset_pattern(packet: dict) -> bool:
    SqNum = packet.get('SqNum', None)
    StNum = packet.get('StNum', None)
    timestampDiff = packet.get('timestampDiff', None)
    return SqNum is not None and StNum is not None and timestampDiff is not None and abs(SqNum - StNum) > 10 and abs(timestampDiff) > 0.5

def rule_masquerade_fake_fault_falsification_consistente(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', None)
    ethSrc = packet.get('ethSrc', None)
    ethDst = packet.get('ethDst', None)
    return cbStatus is not None and ethSrc is not None and ethDst is not None and cbStatus == ethSrc and cbStatus == ethDst

def rule_masquerade_fake_fault_grayhole(packet: dict) -> bool:
    SqNum = packet.get('SqNum', None)
    return SqNum is not None and SqNum < 0

def rule_masquerade_fake_fault_combination(packet: dict) -> bool:
    gooseLengthDiff = packet.get('gooseLengthDiff', None)
    apduSizeDiff = packet.get('apduSizeDiff', None)
    return gooseLengthDiff is not None and apduSizeDiff is not None and abs(gooseLengthDiff - apduSizeDiff) > 10

def rule_masquerade_fake_fault_combination2(packet: dict) -> bool:
    frameLengthDiff = packet.get('frameLengthDiff', None)
    timestampDiff = packet.get('timestampDiff', None)
    return frameLengthDiff is not None and timestampDiff is not None and abs(frameLengthDiff - timestampDiff) > 10

def rule_masquerade_fake_fault_combination3(packet: dict) -> bool:
    delay = packet.get('delay', None)
    timeFromLastChange = packet.get('timeFromLastChange', None)
    return delay is not None and timeFromLastChange is not None and abs(delay - timeFromLastChange) > 10

def rule_masquerade_fake_fault_estatistica(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', None)
    goID = packet.get('goID', None)
    return cbStatus is not None and goID is not None and cbStatus not in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

def rule_masquerade_fake_fault_estatistica2(packet: dict) -> bool:
    stDiff = packet.get('stDiff', None)
    SqNum = packet.get('SqNum', None)
    timestampDiff = packet.get('timestampDiff', None)
    return stDiff is not None and SqNum is not None and timestampDiff is not None and abs(stDiff - SqNum) > 10 and abs(timestampDiff) > 0.5

def rule_masquerade_fake_fault_frequencia(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', None)
    return timestampDiff is not None and timestampDiff < 0.1

def rule_masquerade_fake_fault_frequencia2(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', None)
    return timestampDiff is not None and timestampDiff > 10

def rule_masquerade_fake_fault_replay(packet: dict) -> bool:
    SqNum = packet.get('SqNum', None)
    StNum = packet.get('StNum', None)
    timestampDiff = packet.get('timestampDiff', None)
    return SqNum is not None and StNum is not None and timestampDiff is not None and abs(SqNum - StNum) > 10 and abs(timestampDiff) > 0.5


# === masquerade_fake_normal ===


def rule_masquerade_fake_normal_jumps_stnum_time_diff(packet: dict) -> bool:
    stNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return (stNum > 10 and timestampDiff < 100) or (stNum < 5 and timestampDiff > 500)

def rule_masquerade_fake_normal_sqnum_reset_pattern(packet: dict) -> bool:
    sqNum = packet.get('SqNum', 0)
    stNum = packet.get('StNum', 0)
    return (sqNum == 0 and stNum > 10) or (sqNum == 1 and stNum < 5)

def rule_masquerade_fake_normal_cbstatus_timestamp_diff(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return (cbStatus == 1 and timestampDiff < 100) or (cbStatus == 0 and timestampDiff > 500)

def rule_masquerade_fake_normal_ethsrc_ethdst_cbstatus(packet: dict) -> bool:
    ethSrc = packet.get('ethSrc', '')
    ethDst = packet.get('ethDst', '')
    cbStatus = packet.get('cbStatus', 0)
    return (ethSrc == '00:11:22:33:44:55' and ethDst == '00:66:77:88:99:00' and cbStatus == 1) or (ethSrc == '00:11:22:33:44:55' and ethDst == '00:66:77:88:99:00' and cbStatus == 0)

def rule_masquerade_fake_normal_timestamp_diff_outside_normal_range(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', 0)
    return timestampDiff < 50 or timestampDiff > 1000


# === poisoned_high_rate ===


def rule_poisoned_high_rate_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    prev_st_num = packet.get('prev_st_num', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (sq_num == prev_sq_num and st_num == prev_st_num and timestamp_diff == prev_timestamp_diff)

def rule_poisoned_high_rate_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prev_st_num', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (st_num > prev_st_num and timestamp_diff < prev_timestamp_diff)

def rule_poisoned_high_rate_flood(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (timestamp_diff < prev_timestamp_diff * 0.5)

def rule_poisoned_high_rate_falsification(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    cb_status = packet.get('cbStatus', 0)
    prev_eth_src = packet.get('prev_eth_src', '')
    prev_eth_dst = packet.get('prev_eth_dst', '')
    prev_cb_status = packet.get('prev_cb_status', 0)

    return (eth_src == prev_eth_src and eth_dst == prev_eth_dst and cb_status == prev_cb_status)

def rule_poisoned_high_rate_injection(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    prev_st_num = packet.get('prev_st_num', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (sq_num > prev_sq_num and st_num > prev_st_num and timestamp_diff < prev_timestamp_diff)

def rule_poisoned_high_rate_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (timestamp_diff > prev_timestamp_diff * 2)

def rule_poisoned_high_rate_combination(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    sq_num = packet.get('SqNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prev_st_num', 0)
    prev_sq_num = packet.get('prev_sq_num', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (st_num > prev_st_num and sq_num > prev_sq_num and timestamp_diff < prev_timestamp_diff)

def rule_poisoned_high_rate_statistical_anomaly(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prev_timestamp_diff', 0)

    return (timestamp_diff > prev_timestamp_diff * 5)


# === random_replay ===


def rule_random_replay_replay_consistente(packet: dict) -> bool:
    return packet.get('SqNum') == packet.get('StNum') and packet.get('timestampDiff') == 0

def rule_random_replay_flood_rajada(packet: dict) -> bool:
    return packet.get('timestampDiff') < 10  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_masquerade_falsificacao(packet: dict) -> bool:
    return packet.get('ethSrc') == packet.get('ethDst') and packet.get('cbStatus') != 0

def rule_random_replay_grayhole_desaparecimento(packet: dict) -> bool:
    return packet.get('SqNum') != packet.get('StNum') and packet.get('timestampDiff') > 100  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_timestamp_diff_desvio(packet: dict) -> bool:
    return abs(packet.get('timestampDiff', 0)) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_frame_length_diff_desvio(packet: dict) -> bool:
    return abs(packet.get('frameLengthDiff', 0)) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_goose_length_diff_desvio(packet: dict) -> bool:
    return abs(packet.get('gooseLengthDiff', 0)) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_apdu_size_diff_desvio(packet: dict) -> bool:
    return abs(packet.get('apduSizeDiff', 0)) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_cb_status_diff_desvio(packet: dict) -> bool:
    return abs(packet.get('cbStatusDiff', 0)) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_st_num_incremento_anomalo(packet: dict) -> bool:
    return packet.get('StNum', 0) > packet.get('StNum', 0) + 10  # ajuste a faixa de incremento para a sua rede

def rule_random_replay_sq_num_incremento_anomalo(packet: dict) -> bool:
    return packet.get('SqNum', 0) > packet.get('SqNum', 0) + 10  # ajuste a faixa de incremento para a sua rede

def rule_random_replay_timestamp_diff_incremento_anomalo(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 100  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_frame_length_diff_incremento_anomalo(packet: dict) -> bool:
    return packet.get('frameLengthDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_goose_length_diff_incremento_anomalo(packet: dict) -> bool:
    return packet.get('gooseLengthDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_apdu_size_diff_incremento_anomalo(packet: dict) -> bool:
    return packet.get('apduSizeDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_cb_status_diff_incremento_anomalo(packet: dict) -> bool:
    return packet.get('cbStatusDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_timestamp_diff_alternancia(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 50 and packet.get('timestampDiff', 0) < -50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_frame_length_diff_alternancia(packet: dict) -> bool:
    return packet.get('frameLengthDiff', 0) > 50 and packet.get('frameLengthDiff', 0) < -50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_goose_length_diff_alternancia(packet: dict) -> bool:
    return packet.get('gooseLengthDiff', 0) > 50 and packet.get('gooseLengthDiff', 0) < -50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_apdu_size_diff_alternancia(packet: dict) -> bool:
    return packet.get('apduSizeDiff', 0) > 50 and packet.get('apduSizeDiff', 0) < -50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_cb_status_diff_alternancia(packet: dict) -> bool:
    return packet.get('cbStatusDiff', 0) > 50 and packet.get('cbStatusDiff', 0) < -50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_timestamp_diff_frequencia_irregular(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 100  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_frame_length_diff_frequencia_irregular(packet: dict) -> bool:
    return packet.get('frameLengthDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_goose_length_diff_frequencia_irregular(packet: dict) -> bool:
    return packet.get('gooseLengthDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_apdu_size_diff_frequencia_irregular(packet: dict) -> bool:
    return packet.get('apduSizeDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_cb_status_diff_frequencia_irregular(packet: dict) -> bool:
    return packet.get('cbStatusDiff', 0) > 50  # ajuste a faixa de tempo para a sua rede

def rule_random_replay_st_num_alto_sq_diff_baixo_timestamp_diff_pequeno(packet: dict) -> bool:
    return packet.get('StNum', 0) > 100 and packet.get('SqDiff', 0) < 10 and packet.get('timestampDiff', 0) < 10

def rule_random_replay_cb_status_alterado_go_id_alterado_delay_anomalo(packet: dict) -> bool:
    return packet.get('cbStatus', 0) != 0 and packet.get('goID', 0) != 0 and packet.get('delay', 0) > 100
