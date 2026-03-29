## grayhole


def rule_grayhole_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 0.1 and packet.get('StNum', 0) > 100 and packet.get('cbStatus', 0) == 0

def rule_grayhole_sqnum_reset_pattern(packet: dict) -> bool:
    return packet.get('SqNum', 0) == 1 and packet.get('StNum', 0) == 208 and packet.get('cbStatus', 0) == 1

def rule_grayhole_stnum_jumps(packet: dict) -> bool:
    return packet.get('StNum', 0) > 500 and packet.get('timestampDiff', 0) > 0.05 and packet.get('cbStatus', 0) == 0

def rule_grayhole_timestamp_diff(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 0.2 or packet.get('timestampDiff', 0) < -0.2

def rule_grayhole_cbstatus_diff(packet: dict) -> bool:
    return packet.get('cbStatusDiff', 0) == 1 and packet.get('timestampDiff', 0) > 0.1


## high_StNum


def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.1 and packet['StNum'] > 10000

def rule_high_StNum_sqnum_reset_pattern(packet: dict) -> bool:
    return packet['SqNum'] == 10 and packet['StNum'] == 12485 and packet['cbStatus'] == 0

def rule_high_StNum_stnum_diff(packet: dict) -> bool:
    return packet['StNum'] > 10000 and abs(packet['stDiff']) > 10

def rule_high_StNum_timestamp_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.1 and packet['SqNum'] > 50

def rule_high_StNum_eth_src_dst(packet: dict) -> bool:
    return packet['ethSrc'] == '00:11:22:33:44:55' and packet['ethDst'] == '00:66:77:88:99:00'

def rule_high_StNum_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 0.1 and packet.get('StNum', 0) > 10000

def rule_high_StNum_sqnum_reset_pattern(packet: dict) -> bool:
    return packet.get('SqNum', 0) == 10 and packet.get('StNum', 0) == 12485 and packet.get('cbStatus', 0) == 0

def rule_high_StNum_stnum_diff(packet: dict) -> bool:
    return packet.get('StNum', 0) > 10000 and abs(packet.get('stDiff', 0)) > 10

def rule_high_StNum_timestamp_diff(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 0.1 and packet.get('SqNum', 0) > 50

def rule_high_StNum_eth_src_dst(packet: dict) -> bool:
    return packet.get('ethSrc', '') == '00:11:22:33:44:55' and packet.get('ethDst', '') == '00:66:77:88:99:00'


## injection


def rule_injection_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.1 and packet['stDiff'] > 50 and packet['SqNum'] > 80

def rule_injection_sqnum_reset_pattern(packet: dict) -> bool:
    return packet['SqNum'] == packet['SqNum'] - 1 and packet['StNum'] == packet['StNum'] + 1 and packet['cbStatus'] == 0

def rule_injection_stnum_jumps_time_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.05 and packet['stDiff'] > 20 and packet['StNum'] > 60

def rule_injection_cbstatus_diff(packet: dict) -> bool:
    return packet['cbStatusDiff'] == 1 and packet['timestampDiff'] > 0.01 and packet['SqNum'] > 30

def rule_injection_ethsrc_dst_diff(packet: dict) -> bool:
    return packet['ethSrc'] != packet['ethDst'] and packet['timestampDiff'] > 0.05 and packet['SqNum'] > 40


## inverse_replay


def rule_inverse_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet.get('StNum', 0) > 100 and packet.get('timestampDiff', 0) > 0.1

def rule_inverse_replay_sqnum_reset_pattern(packet: dict) -> bool:
    return packet.get('SqNum', 0) == 1 and packet.get('StNum', 0) == 9 and packet.get('timestampDiff', 0) < 0.001

def rule_inverse_replay_cbstatus_diff_pattern(packet: dict) -> bool:
    return packet.get('cbStatus', 0) == 0 and packet.get('cbStatusDiff', 0) == 1 and packet.get('timestampDiff', 0) > 0.01

def rule_inverse_replay_ethsrc_dst_pattern(packet: dict) -> bool:
    return packet.get('ethSrc', '') == '00:11:22:33:44:55' and packet.get('ethDst', '') == '00:66:77:88:99:00' and packet.get('timestampDiff', 0) > 0.1

def rule_inverse_replay_appid_diff_pattern(packet: dict) -> bool:
    return packet.get('appID', 0) == 123 and packet.get('appIDDiff', 0) == 1 and packet.get('timestampDiff', 0) > 0.01


## masquerade_fake_fault


def rule_masquerade_fake_fault_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 0.1 and packet.get('StNum', 0) > 200 and packet.get('cbStatus', 0) == 1

def rule_masquerade_fake_fault_sqnum_reset_pattern(packet: dict) -> bool:
    return packet.get('SqNum', 0) > 10 and packet.get('stDiff', 0) < -50 and packet.get('sqDiff', 0) > 10

def rule_masquerade_fake_fault_src_dst_pattern(packet: dict) -> bool:
    return packet.get('ethSrc', '') == '00:11:22:33:44:55' and packet.get('ethDst', '') == '00:66:77:88:99:00' and packet.get('SqNum', 0) > 20

def rule_masquerade_fake_fault_cbstatus_diff(packet: dict) -> bool:
    return packet.get('cbStatusDiff', 0) == 1 and packet.get('SqNum', 0) > 10 and packet.get('timestampDiff', 0) > 0.05

def rule_masquerade_fake_fault_stnum_diff(packet: dict) -> bool:
    return packet.get('stDiff', 0) < -30 and packet.get('SqNum', 0) > 10 and packet.get('timestampDiff', 0) > 0.1


## masquerade_fake_normal


def rule_masquerade_fake_normal_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet.get('StNum', 0) > 1000 and packet.get('timestampDiff', 0) > 0.1

def rule_masquerade_fake_normal_sqnum_reset_pattern(packet: dict) -> bool:
    return packet.get('SqNum', 0) == 4 and packet.get('StNum', 0) == 54 and packet.get('timestampDiff', 0) == 0.025

def rule_masquerade_fake_normal_cbstatus_diff(packet: dict) -> bool:
    return packet.get('cbStatus', 0) == 0 and packet.get('cbStatusDiff', 0) == 1

def rule_masquerade_fake_normal_ethsrc_dst_diff(packet: dict) -> bool:
    return packet.get('ethSrc', '') != packet.get('ethDst', '')

def rule_masquerade_fake_normal_appid_diff(packet: dict) -> bool:
    return packet.get('appID', '') != 'IntLockA'


## poisoned_high_rate


def rule_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet.get('StNum', 0) > 1000 and packet.get('timestampDiff', 0) > 10

def rule_sqnum_reset_pattern(packet: dict) -> bool:
    return packet.get('SqNum', 0) > 1000 and packet.get('cbStatus', 0) == 0 and packet.get('stDiff', 0) == 0

def rule_high_rate_sqnum(packet: dict) -> bool:
    return packet.get('SqNum', 0) > 1000 and packet.get('timestampDiff', 0) > 5 and packet.get('cbStatus', 0) == 1

def rule_anomalous_eth_src_dst(packet: dict) -> bool:
    return packet.get('ethSrc', '') != packet.get('ethDst', '') and packet.get('StNum', 0) > 1000 and packet.get('SqNum', 0) > 1000

def rule_timestamp_diff_outlier(packet: dict) -> bool:
    return abs(packet.get('timestampDiff', 0)) > 100


## random_replay


def rule_random_replay_jumps_stnum_time_diff(packet: dict) -> bool:
    return packet.get('StNum', 0) > 500 and packet.get('timestampDiff', 0) > 0.1

def rule_random_replay_sqnum_reset_pattern(packet: dict) -> bool:
    return packet.get('SqNum', 0) == 1 and packet.get('StNum', 0) == 573

def rule_random_replay_cbstatus_diff(packet: dict) -> bool:
    return packet.get('cbStatus', 0) == 0 and packet.get('cbStatusDiff', 0) == 1

def rule_random_replay_timestamp_diff(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 0.05

def rule_random_replay_stnum_diff(packet: dict) -> bool:
    return abs(packet.get('StNum', 0) - packet.get('StNum', 0).max()) > 200
