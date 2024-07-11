#
# Copyright (c) 2024 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import datetime
import os
import sys

# Get the directory in which this file is located.
current_file_dir_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))

# Get the directory in which the source code is located.
source_dir_path = os.path.abspath(os.path.join(current_file_dir_path, '..'))

# Append the parent path to the system paths, so the code in the directory
# above may be imported.
sys.path.append(source_dir_path)

from access_data import AccessData
from access_extension import AccessExtension
from non_access_extension import NonAccessExtension
from access_rule import AccessRule
from access_rule import AccessRuleCapabilitiesBits
from access_rule import AccessRuleScheduleIds
from access_rule import AccessRuleScheduleIdsBits
from schedule import Schedule
from schedule import ScheduleFlagBits
from utility import Utility
from recurrence_rule import RecurrenceRulePatternType
from recurrence_rule import RecurrenceRuleMaskBits_Weekdays

from access_extension_data.secure_pin_extension_data import ReaderPin
from access_extension_data.secure_pin_extension_data import SecurePinExtensionData

from access_extension_data.multiple_users_extension_data import MultipleUsersExtensionData

from mdl.device_response_builder import DeviceResponseBuilder

# Create the Access Data Element object.
access_data = AccessData()
access_data.version = 1
access_data.id.extend([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF])

# Create an Access Rule that allows securing and unsecuring during schedules
# 1 and 3, while denying access during schedule 2.
access_rule = AccessRule()
access_rule.capabilities = AccessRuleCapabilitiesBits.SECURE | AccessRuleCapabilitiesBits.UNSECURE
access_rule.allow_schedule_ids.append(AccessRuleScheduleIds.SCHEDULE_1)
access_rule.allow_schedule_ids.append(AccessRuleScheduleIds.SCHEDULE_3)
access_rule.deny_schedule_ids.append(AccessRuleScheduleIds.SCHEDULE_2)
access_data.access_rules.append(access_rule)

# Create an Access Rule that allows all capabilities during schedules 1 and 3.
access_rule = AccessRule()
access_rule.capabilities = AccessRuleCapabilitiesBits.ALL_CAPABILITIES
access_rule.allow_schedule_id_bits = AccessRuleScheduleIdsBits.SCHEDULE_1 | AccessRuleScheduleIdsBits.SCHEDULE_3
access_data.access_rules.append(access_rule)

# Create Schedule 1.
schedule = Schedule()
schedule.flags = ScheduleFlagBits.TIME_IN_UTC
schedule.start_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 1
schedule.end_time = schedule.start_time + (90 * 24 * 60 * 60)
schedule.rrule.duration_seconds = 3600
schedule.rrule.pattern = RecurrenceRulePatternType.WEEKLY
schedule.rrule.interval = 3
schedule.rrule.mask = RecurrenceRuleMaskBits_Weekdays.MONDAY | RecurrenceRuleMaskBits_Weekdays.WEDNESDAY | RecurrenceRuleMaskBits_Weekdays.FRIDAY
access_data.schedules.append(schedule)

# Create Schedule 2.
schedule = Schedule()
schedule.flags = 0
schedule.start_time = Utility.time_val_to_seconds(datetime.datetime.now()) + 2
schedule.end_time = schedule.start_time + (90 * 24 * 60 * 60)
schedule.rrule.duration_seconds = 7200
schedule.rrule.pattern = RecurrenceRulePatternType.WEEKLY
schedule.rrule.interval = 1
schedule.rrule.mask = RecurrenceRuleMaskBits_Weekdays.TUESDAY | RecurrenceRuleMaskBits_Weekdays.THURSDAY | RecurrenceRuleMaskBits_Weekdays.WEEKENDS
access_data.schedules.append(schedule)

# Create Schedule 3.
schedule = Schedule()
schedule.flags = ScheduleFlagBits.TIME_IN_UTC
schedule.start_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 3
schedule.end_time = schedule.start_time + (90 * 24 * 60 * 60)
schedule.rrule.duration_seconds = 1800
schedule.rrule.pattern = RecurrenceRulePatternType.MONTHLY_BY_DATE
schedule.rrule.interval = 2
schedule.rrule.ordinal = -1
schedule.rrule.mask = RecurrenceRuleMaskBits_Weekdays.FRIDAY
access_data.schedules.append(schedule)

# Set a couple Reader Rules.
access_data.reader_rule_ids.append(123)
access_data.reader_rule_ids.append(456)

# Create a Secure Pin Access Extension.
secure_pin_extension = AccessExtension()
secure_pin_extension.id = 1
secure_pin_extension.is_critical = True
secure_pin_extension.version = 1
secure_pin_extension.data = SecurePinExtensionData()
secure_pin_extension.data.pin_keyed_hashes.append(bytearray(range(0x30, 0x40)))
secure_pin_extension.data.issuer_public_key.append(0x04)
secure_pin_extension.data.issuer_public_key.extend(range(1, 65))
reader_pin = ReaderPin()
reader_pin.reader_public_key_hash.extend(range(0x20, 0x30))
reader_pin.pin_keyed_hash.extend(range(0x40, 0x50))
secure_pin_extension.data.reader_pins.append(reader_pin)

# Create a Multiple Users Access Extension.
multiple_users_extension = AccessExtension()
multiple_users_extension.id = 2
multiple_users_extension.is_critical = True
multiple_users_extension.version = 1
multiple_users_extension.data = MultipleUsersExtensionData()
multiple_users_extension.data.timeout_seconds = MultipleUsersExtensionData.TIMEOUT_SECONDS_DEFAULT
multiple_users_extension.data.access_points = 1
multiple_users_extension.data.required_access_points = 2
multiple_users_extension.data.user_limit = 2

# Set the Access Extensions at the Registered Vendor ID.
access_data.access_extensions[0xFA1466] = [secure_pin_extension, multiple_users_extension]

# Output the Access Data Element in JSON, CBOR, and TLV.
print("\nAccess Data Element")
print("json: " + access_data.to_json() + "\n")
cbor = access_data.to_cbor()
print("cbor: " + "".join("{:02X}".format(v) for v in cbor) + "\n")
tlv = access_data.to_tlv()
print("tlv: " + "".join("{:02X}".format(v) for v in tlv) + "\n")

# Build a Device Response containing the Access Data Element.
device_response = DeviceResponseBuilder.build([access_data], None)

print("Device Response")
cbor = device_response.to_cbor()
if (cbor is not None):
    print("cbor: " + "".join("{:02X}".format(v) for v in cbor) + "\n")
