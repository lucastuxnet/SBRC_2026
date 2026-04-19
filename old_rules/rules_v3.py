## grayhole
def rule_grayhole_stnum_sqdiff(packet: dict) -> bool:
    """Detect grayhole attack based on StNum and sqDiff being zero."""
    return packet.get('StNum') == 0.0 and packet.get('sqDiff') == 0.0

def rule_grayhole_timestampdiff(packet: dict) -> bool:
    """Detect grayhole attack when timestampDiff is zero and tDiff is unusually low."""
    return packet.get('timestampDiff') == 0.0 and packet.get('tDiff') == 0.0

def rule_grayhole_low_variance(packet: dict) -> bool:
    """Detect grayhole attack by checking low variance in key fields."""
    return (packet.get('StNum') == 0.0 and
            packet.get('sqDiff') == 0.0 and
            packet.get('timestampDiff') == 0.0 and
            packet.get('tDiff') == 0.0)

def rule_grayhole_apdusize(packet: dict) -> bool:
    """Detect grayhole attack when APDUSize matches the constant normal value but other indicators are zero."""
    return packet.get('APDUSize') == 186.0 and packet.get('StNum') == 0.0

def rule_grayhole_combined(packet: dict) -> bool:
    """Combined heuristic for grayhole detection."""
    return (packet.get('StNum') == 0.0 and
            packet.get('sqDiff') == 0.0 and
            packet.get('timestampDiff') == 0.0 and
            packet.get('APDUSize') == 186.0)


## grayhole
def rule_grayhole_timestamp_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.01

def rule_grayhole_st_diff(packet: dict) -> bool:
    return abs(packet['stDiff']) > 10

def rule_grayhole_sq_diff(packet: dict) -> bool:
    return abs(packet['sqDiff']) > 10

def rule_grayhole_cb_status_diff(packet: dict) -> bool:
    return packet['cbStatusDiff'] > 0

def rule_grayhole_apdu_size_diff(packet: dict) -> bool:
    return packet['apduSizeDiff'] > 0

def rule_grayhole_frame_length_diff(packet: dict) -> bool:
    return packet['frameLengthDiff'] > 0

def rule_grayhole_time_from_last_change(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 10

def rule_grayhole_delay(packet: dict) -> bool:
    return packet['delay'] > 0.01

def rule_grayhole_class(packet: dict) -> bool:
    return packet['class'] == 'grayhole'

## injection

def rule_injection_st_diff(packet: dict) -> bool:
    return packet['stDiff'] > 50

def rule_injection_sq_diff(packet: dict) -> bool:
    return packet['sqDiff'] > 50

def rule_injection_cb_status_diff(packet: dict) -> bool:
    return packet['cbStatusDiff'] > 0

def rule_injection_apdu_size_diff(packet: dict) -> bool:
    return packet['apduSizeDiff'] > 0

def rule_injection_frame_length_diff(packet: dict) -> bool:
    return packet['frameLengthDiff'] > 0

def rule_injection_timestamp_diff(packet: dict) -> bool:
    return packet['timestampDiff'] > 0.01

def rule_injection_class(packet: dict) -> bool:
    return packet['class'] == 'injection'

def rule_injection_sq_num(packet: dict) -> bool:
    return packet['SqNum'] > 80

def rule_injection_st_num(packet: dict) -> bool:
    return packet['StNum'] > 40

def rule_injection_cb_status(packet: dict) -> bool:
    return packet['cbStatus'] == 1

def rule_injection_eth_type(packet: dict) -> bool:
    return packet['ethType'] == 0x88B8

def rule_injection_goos_appid(packet: dict) -> bool:
    return packet['gooseAppid'] == 0x00003001

def rule_injection_goos_len(packet: dict) -> bool:
    return packet['gooseLen'] == 186

def rule_injection_tpid(packet: dict) -> bool:
    return packet['TPID'] == 0x8100

def rule_injection_gocb_ref(packet: dict) -> bool:
    return packet['gocbRef'] == 'LD/LLN0$GO$gcblA'

def rule_injection_dat_set(packet: dict) -> bool:
    return packet['datSet'] == 'LD/LLN0$IntLockA'

def rule_injection_go_id(packet: dict) -> bool:
    return packet['goID'] == 'IntLockA'

def rule_injection_test(packet: dict) -> bool:
    return packet['test'] == False

def rule_injection_conf_rev(packet: dict) -> bool:
    return packet['confRev'] == 1.0

def rule_injection_num_dat_set_entries(packet: dict) -> bool:
    return packet['numDatSetEntries'] == 25.0

def rule_injection_apdu_size(packet: dict) -> bool:
    return packet['APDUSize'] == 186.0

def rule_injection_time_from_last_change(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 0.01


## poisoned_high_rate


def rule_poisoned_high_rate_stnum(packet: dict) -> bool:
    return packet['StNum'] > 6500

def rule_poisoned_high_rate_sqnum(packet: dict) -> bool:
    return packet['SqNum'] > 1000

def rule_poisoned_high_rate_timestampdiff(packet: dict) -> bool:
    return packet['timestampDiff'] > 30000

def rule_poisoned_high_rate_tdiff(packet: dict) -> bool:
    return packet['tDiff'] > 10

def rule_poisoned_high_rate_timefromlastchange(packet: dict) -> bool:
    return packet['timeFromLastChange'] > 20000

def rule_poisoned_high_rate_delay(packet: dict) -> bool:
    return packet['delay'] > 10000

def rule_poisoned_high_rate_class(packet: dict) -> bool:
    return packet['class'] == 'poisoned_high_rate'
