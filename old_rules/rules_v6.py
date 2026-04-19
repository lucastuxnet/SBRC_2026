

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


# === inverse_replay ===


def rule_inverse_replay_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return sq_num != st_num and timestamp_diff > 0 and (sq_num - st_num) != timestamp_diff

def rule_inverse_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    return abs(sq_num - st_num) > 1 and timestamp_diff < 100

def rule_inverse_replay_cb_status_diff(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    cb_status_diff = packet.get('cbStatusDiff', 0)
    return cb_status_diff != 0 and cb_status_diff != (cb_status - packet.get('cbStatus', 0))

def rule_inverse_replay_eth_src_dst(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    st_num = packet.get('StNum', 0)
    return eth_src != packet.get('ethSrc', '') or eth_dst != packet.get('ethDst', '') or st_num != packet.get('StNum', 0)

def rule_inverse_replay_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    return sq_num < st_num and (sq_num - st_num) > 10

def rule_inverse_replay_flood(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    sq_num = packet.get('SqNum', 0)
    return timestamp_diff < 10 and sq_num > 100


# === masquerade_fake_fault ===


def rule_masquerade_fake_fault_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num) != (st_num - prev_st_num) or abs(timestamp_diff - prev_timestamp_diff) > 10

def rule_masquerade_fake_fault_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    sq_num_diff = sq_num - prev_sq_num
    st_num_diff = st_num - prev_st_num
    timestamp_diff_diff = abs(timestamp_diff - prev_timestamp_diff)

    return (sq_num_diff > 10 or st_num_diff > 10) and timestamp_diff_diff > 10

def rule_masquerade_fake_fault_cb_status_diff(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    cb_status_diff = packet.get('cbStatusDiff', 0)
    prev_cb_status = packet.get('prevCbStatus', 0)
    prev_cb_status_diff = packet.get('prevCbStatusDiff', 0)

    return cb_status != prev_cb_status or cb_status_diff != prev_cb_status_diff

def rule_masquerade_fake_fault_interval_irregular(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)
    t_diff = packet.get('tDiff', 0)
    prev_t_diff = packet.get('prevTDiff', 0)

    return abs(timestamp_diff - prev_timestamp_diff) > 10 or abs(t_diff - prev_t_diff) > 10

def rule_masquerade_fake_fault_freq_anomalous(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    sq_num_diff = sq_num - prev_sq_num
    st_num_diff = st_num - prev_st_num
    timestamp_diff_diff = abs(timestamp_diff - prev_timestamp_diff)

    return (sq_num_diff > 10 or st_num_diff > 10) and timestamp_diff_diff > 10

def rule_masquerade_fake_fault_origin_destination_anomalous(packet: dict) -> bool:
    eth_src = packet.get('ethSrc', '')
    eth_dst = packet.get('ethDst', '')
    prev_eth_src = packet.get('prevEthSrc', '')
    prev_eth_dst = packet.get('prevEthDst', '')

    return eth_src != prev_eth_src or eth_dst != prev_eth_dst

def rule_masquerade_fake_fault_diff_size_anomalous(packet: dict) -> bool:
    apdu_size_diff = packet.get('apduSizeDiff', 0)
    frame_length_diff = packet.get('frameLengthDiff', 0)
    prev_apdu_size_diff = packet.get('prevApduSizeDiff', 0)
    prev_frame_length_diff = packet.get('prevFrameLengthDiff', 0)

    return apdu_size_diff != prev_apdu_size_diff or frame_length_diff != prev_frame_length_diff


# === masquerade_fake_normal ===


def rule_masquerade_fake_normal_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num - prev_sq_num) != 1 or (st_num - prev_st_num) != 1 or abs(timestamp_diff - prev_timestamp_diff) < 10

def rule_masquerade_fake_normal_jumps_stnum_time_diff(packet: dict) -> bool:
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return abs(st_num - prev_st_num) > 10 or abs(timestamp_diff - prev_timestamp_diff) > 100

def rule_masquerade_fake_normal_sqnum_reset_pattern(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    prev_sq_num = packet.get('prevSqNum', 0)

    return sq_num < prev_sq_num

def rule_masquerade_fake_normal_cbstatus_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)
    prev_cb_status = packet.get('prevCbStatus', 0)
    prev_go_id = packet.get('prevGoID', 0)

    return cb_status != prev_cb_status or go_id != prev_go_id

def rule_masquerade_fake_normal_anomalous_frequency(packet: dict) -> bool:
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return abs(timestamp_diff - prev_timestamp_diff) < 10

def rule_masquerade_fake_normal_reset_sequence(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)

    return sq_num < prev_sq_num or st_num < prev_st_num


# === poisoned_high_rate ===


def rule_poisoned_high_rate_replay(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num == prev_sq_num and st_num == prev_st_num and timestamp_diff > 2 * prev_timestamp_diff)

def rule_poisoned_high_rate_jumps_stnum_time_diff(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (abs(st_num - prev_st_num) > 10 and abs(sq_num - prev_sq_num) > 10 and timestamp_diff < 0.1 * prev_timestamp_diff)

def rule_poisoned_high_rate_flood(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (sq_num == prev_sq_num and st_num == prev_st_num and timestamp_diff < 0.1 * prev_timestamp_diff)

def rule_poisoned_high_rate_falsification(packet: dict) -> bool:
    cb_status = packet.get('cbStatus', 0)
    go_id = packet.get('goID', 0)

    return (cb_status == 1 and go_id == 1)

def rule_poisoned_high_rate_injection(packet: dict) -> bool:
    sq_num = packet.get('SqNum', 0)
    st_num = packet.get('StNum', 0)
    timestamp_diff = packet.get('timestampDiff', 0)
    prev_sq_num = packet.get('prevSqNum', 0)
    prev_st_num = packet.get('prevStNum', 0)
    prev_timestamp_diff = packet.get('prevTimestampDiff', 0)

    return (abs(st_num - prev_st_num) > 100 and abs(sq_num - prev_sq_num) > 100 and timestamp_diff > 10 * prev_timestamp_diff)


# === random_replay ===


def rule_random_replay_replay(packet: dict) -> bool:
    SqNum = packet.get('SqNum', 0)
    StNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return (SqNum > StNum) and (timestampDiff > 1000) and (timestampDiff < 5000)

def rule_random_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    SqNum = packet.get('SqNum', 0)
    StNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return (abs(SqNum - StNum) > 10) and (timestampDiff > 1000) and (timestampDiff < 5000)

def rule_random_replay_cb_status_diff(packet: dict) -> bool:
    cbStatus = packet.get('cbStatus', 0)
    cbStatusDiff = packet.get('cbStatusDiff', 0)
    return (abs(cbStatusDiff) > 10) and (cbStatusDiff != 0)

def rule_random_replay_timestamp_diff_time_from_last_change(packet: dict) -> bool:
    timestampDiff = packet.get('timestampDiff', 0)
    timeFromLastChange = packet.get('timeFromLastChange', 0)
    return (timestampDiff > 1000) and (timestampDiff < 5000) and (timeFromLastChange > 1000) and (timeFromLastChange < 5000)

def rule_random_replay_eth_src_dst(packet: dict) -> bool:
    ethSrc = packet.get('ethSrc', '')
    ethDst = packet.get('ethDst', '')
    SqNum = packet.get('SqNum', 0)
    StNum = packet.get('StNum', 0)
    return (len(ethSrc) > 10) and (len(ethDst) > 10) and (abs(SqNum - StNum) > 10)

def rule_random_replay_flood(packet: dict) -> bool:
    SqNum = packet.get('SqNum', 0)
    StNum = packet.get('StNum', 0)
    timestampDiff = packet.get('timestampDiff', 0)
    return (abs(SqNum - StNum) > 100) and (timestampDiff < 100)
