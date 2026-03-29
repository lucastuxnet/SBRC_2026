

## grayhole


def rule_grayhole_timestamp_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.05

def rule_grayhole_st_diff(packet: dict) -> bool:
    return abs(packet['stDiff']) > 50

def rule_grayhole_sq_diff(packet: dict) -> bool:
    return abs(packet['sqDiff']) > 10

def rule_grayhole_cb_status(packet: dict) -> bool:
    return packet['cbStatus'] == 0

def rule_grayhole_class(packet: dict) -> bool:
    return packet['class'] == 'grayhole'

def rule_grayhole_time_from_last_change(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 10

def rule_grayhole_delay(packet: dict) -> bool:
    return packet['delay'] > 0.01

def rule_grayhole_suspicious(packet: dict) -> bool:
    return (rule_grayhole_timestamp_diff(packet) or
            rule_grayhole_st_diff(packet) or
            rule_grayhole_sq_diff(packet) or
            rule_grayhole_cb_status(packet) or
            rule_grayhole_class(packet) or
            rule_grayhole_time_from_last_change(packet) or
            rule_grayhole_delay(packet))


## high_StNum


def rule_high_StNum_StNum(packet: dict) -> bool:
    return packet['StNum'] > 10000

def rule_high_StNum_SqNum(packet: dict) -> bool:
    return packet['SqNum'] > 100

def rule_high_StNum_timestampDiff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.1

def rule_high_StNum_StDiff(packet: dict) -> bool:
    return packet['stDiff'] > 10000

def rule_high_StNum_SqDiff(packet: dict) -> bool:
    return packet['sqDiff'] > 10

def rule_high_StNum_goosLengthDiff(packet: dict) -> bool:
    return packet['gooseLengthDiff'] > 0

def rule_high_StNum_cbStatusDiff(packet: dict) -> bool:
    return packet['cbStatusDiff'] > 0

def rule_high_StNum_apduSizeDiff(packet: dict) -> bool:
    return packet['apduSizeDiff'] > 0

def rule_high_StNum_frameLengthDiff(packet: dict) -> bool:
    return packet['frameLengthDiff'] > 0

def rule_high_StNum_timeFromLastChange(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 100

def rule_high_StNum_delay(packet: dict) -> bool:
    return packet['delay'] < 0


## injection


def rule_injection_st_diff(packet: dict) -> bool:
    return packet['stDiff'] < -100

def rule_injection_sq_diff(packet: dict) -> bool:
    return packet['sqDiff'] > 50

def rule_injection_cb_status(packet: dict) -> bool:
    return packet['cbStatus'] == 0

def rule_injection_timestamp_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.05

def rule_injection_time_from_last_change(packet: dict) -> bool:
    return packet['timeFromLastChange'] < -50

def rule_injection_delay(packet: dict) -> bool:
    return packet['delay'] < -50

def rule_injection_class(packet: dict) -> bool:
    return packet['class'] == 'injection'

def rule_injection_st_num(packet: dict) -> bool:
    return packet['StNum'] > 80

def rule_injection_sq_num(packet: dict) -> bool:
    return packet['SqNum'] > 80

def rule_injection_cb_status_diff(packet: dict) -> bool:
    return packet['cbStatusDiff'] == 1

def rule_injection_apdu_size_diff(packet: dict) -> bool:
    return packet['apduSizeDiff'] == 0

def rule_injection_frame_length_diff(packet: dict) -> bool:
    return packet['frameLengthDiff'] == 0


## inverse_replay


def rule_inverse_replay_timestamp_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.01

def rule_inverse_replay_st_num(packet: dict) -> bool:
    return packet['StNum'] < 10

def rule_inverse_replay_sq_num(packet: dict) -> bool:
    return packet['SqNum'] < 10

def rule_inverse_replay_cb_status(packet: dict) -> bool:
    return packet['cbStatus'] == 0

def rule_inverse_replay_time_from_last_change(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 1000

def rule_inverse_replay_delay(packet: dict) -> bool:
    return packet['delay'] > 10

def rule_inverse_replay_class(packet: dict) -> bool:
    return packet['class'] == 'inverse_replay'

def rule_inverse_replay_inverse_replay(packet: dict) -> bool:
    return packet['class'] != 'normal'

def rule_inverse_replay_timestamp_diff_large(packet: dict) -> bool:
    return packet['timestampDiff'] > 1

def rule_inverse_replay_st_num_large(packet: dict) -> bool:
    return packet['StNum'] > 500

def rule_inverse_replay_sq_num_large(packet: dict) -> bool:
    return packet['SqNum'] > 50

def rule_inverse_replay_cb_status_zero(packet: dict) -> bool:
    return packet['cbStatus'] == 0

def rule_inverse_replay_time_from_last_change_large(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 5000

def rule_inverse_replay_delay_large(packet: dict) -> bool:
    return packet['delay'] > 100

def rule_inverse_replay_class_inverse_replay(packet: dict) -> bool:
    return packet['class'] == 'inverse_replay'

def rule_inverse_replay_inverse_replay_inverse(packet: dict) -> bool:
    return packet['class'] != 'normal'


## masquerade_fake_fault


def rule_masquerade_fake_fault_stnum_diff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and abs(packet['StNum'] - packet['SqNum']) > 100

def rule_masquerade_fake_fault_timestamp_diff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and packet['timestampDiff'] > 0.05

def rule_masquerade_fake_fault_sqnum_diff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and abs(packet['SqNum'] - packet['SqNum']) > 10

def rule_masquerade_fake_fault_cbstatus_diff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and packet['cbStatusDiff'] == 1

def rule_masquerade_fake_fault_stdiff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and abs(packet['stDiff']) > 1000

def rule_masquerade_fake_fault_sqdiff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and abs(packet['sqDiff']) > 10

def rule_masquerade_fake_fault_gooselengthdiff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and packet['gooseLengthDiff'] != 0

def rule_masquerade_fake_fault_apdusize_diff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and packet['apduSizeDiff'] != 0

def rule_masquerade_fake_fault_frame_length_diff(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and packet['frameLengthDiff'] != 0

def rule_masquerade_fake_fault_timefromlastchange(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and packet['timeFromLastChange'] > 10

def rule_masquerade_fake_fault_delay(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_fault' and packet['delay'] > 1


## masquerade_fake_normal


def rule_masquerade_fake_normal_stnum(packet: dict) -> bool:
    return packet['StNum'] > 1000

def rule_masquerade_fake_normal_sqnum(packet: dict) -> bool:
    return packet['SqNum'] > 1000

def rule_masquerade_fake_normal_timestampdiff(packet: dict) -> bool:
    return packet['timestampDiff'] == 0.006310

def rule_masquerade_fake_normal_sqdiff(packet: dict) -> bool:
    return packet['sqDiff'] < -10

def rule_masquerade_fake_normal_cbstatus(packet: dict) -> bool:
    return packet['cbStatus'] == 0.0

def rule_masquerade_fake_normal_class(packet: dict) -> bool:
    return packet['class'] == 'masquerade_fake_normal'

def rule_masquerade_fake_normal_stdiff(packet: dict) -> bool:
    return packet['stDiff'] < -100

def rule_masquerade_fake_normal_apdusize(packet: dict) -> bool:
    return packet['apduSizeDiff'] == 1.0

def rule_masquerade_fake_normal_frame_length_diff(packet: dict) -> bool:
    return packet['frameLengthDiff'] == 0.0

def rule_masquerade_fake_normal_timefromlastchange(packet: dict) -> bool:
    return packet['timeFromLastChange'] == 0.0


## poisoned_high_rate


def rule_poisoned_high_rate_stnum(packet: dict) -> bool:
    return packet['StNum'] > 6500

def rule_poisoned_high_rate_sqnum(packet: dict) -> bool:
    return packet['SqNum'] > 6500

def rule_poisoned_high_rate_timestampdiff(packet: dict) -> bool:
    return packet['timestampDiff'] > 4

def rule_poisoned_high_rate_tdiff(packet: dict) -> bool:
    return packet['tDiff'] > 0.1

def rule_poisoned_high_rate_timefromlastchange(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 30000

def rule_poisoned_high_rate_delay(packet: dict) -> bool:
    return packet['delay'] > 10

def rule_poisoned_high_rate_class(packet: dict) -> bool:
    return packet['class'] == 'poisoned_high_rate'



## random_replay


def rule_random_replay_timestamp_diff(packet: dict) -> bool:
    return packet['timestampDiff'] == 0

def rule_random_replay_st_diff(packet: dict) -> bool:
    return packet['stDiff'] == 0

def rule_random_replay_sq_diff(packet: dict) -> bool:
    return packet['sqDiff'] == 0

def rule_random_replay_goose_length_diff(packet: dict) -> bool:
    return packet['gooseLengthDiff'] == 0

def rule_random_replay_cb_status_diff(packet: dict) -> bool:
    return packet['cbStatusDiff'] == 0

def rule_random_replay_apdu_size_diff(packet: dict) -> bool:
    return packet['apduSizeDiff'] == 0

def rule_random_replay_frame_length_diff(packet: dict) -> bool:
    return packet['frameLengthDiff'] == 0

def rule_random_replay_time_from_last_change(packet: dict) -> bool:
    return packet['timeFromLastChange'] == 0

def rule_random_replay_delay(packet: dict) -> bool:
    return packet['delay'] == 0

def rule_random_replay_class(packet: dict) -> bool:
    return packet['class'] == 'random_replay'
