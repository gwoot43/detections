---
id: DV05
name: Device installation blocked by policy (network adapter, keyboard, storage or phone; any block on a server; repeated attempts)
category: device
status: todo
rank: 4
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1200, T1052.001]
data_source: Windows Security 6423 (installation of this device is forbidden by system policy)
suppression:
  fields: [host_key, subject_user]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
6423 is written when Windows refuses to install a device because a **Device Installation Restrictions** policy forbids its ID or class. The control worked. The alert is about the **attempt**: someone tried to attach a device you've already decided must not be used.

The rule keeps the attempts that matter:
- **A network adapter, keyboard or HID, Bluetooth adapter or modem anywhere.** These are the classes used to bridge networks or inject keystrokes.
- **Any block on a server.**
- **Three or more different devices blocked on one host within an hour.** That's someone working through hardware until one gets past the policy.

A single blocked USB stick on a laptop doesn't alert. The insider process can still report on those from the same data.

## Prerequisite
- **Audit PNP Activity** set to Success, and a Device Installation Restrictions policy in place (GPO: Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions, or the Intune Device Control profile). Without a restriction policy nothing is ever blocked, and this rule is silent.
- 6423 records the device class as a **GUID**, not a name, so the query maps the standard class GUIDs.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "6423"
| EVAL class_guid = TO_LOWER(COALESCE(winlog.event_data.ClassId, "")),
       cls = CASE(
         class_guid LIKE "*4d36e972-e325-11ce-bfc1-08002be10318*", "net",
         class_guid LIKE "*4d36e96b-e325-11ce-bfc1-08002be10318*", "keyboard",
         class_guid LIKE "*745a17a0-74d3-11d0-b6fe-00a0c90f57da*", "hid",
         class_guid LIKE "*e0cbf06c-cd8b-4647-bb8a-263b43f0f974*", "bluetooth",
         class_guid LIKE "*4d36e96d-e325-11ce-bfc1-08002be10318*", "modem",
         class_guid LIKE "*4d36e967-e325-11ce-bfc1-08002be10318*", "diskdrive",
         class_guid LIKE "*eec5ad98-8080-425f-922a-dabf3de3f69a*", "wpd",
         class_guid LIKE "*36fc9e60-c465-11cf-8056-444553540000*", "usb",
         "other"),
       host_key = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), "."))),
       subject_user = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       os = TO_LOWER(COALESCE(host.os.name, "")),
       risky_class = CASE(cls IN ("net", "keyboard", "hid", "bluetooth", "modem"), 1, 0),
       on_server = CASE(os LIKE "*server*", 1, 0)
| STATS blocked_devices = COUNT_DISTINCT(device.id), risky = MAX(risky_class), server = MAX(on_server),
        classes = VALUES(cls), devices = VALUES(device.model.name), device_ids = VALUES(device.id),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host_key, subject_user
| WHERE risky == 1 OR server == 1 OR blocked_devices >= 3
| EVAL reason = CASE(risky == 1, "network, keyboard or hid device blocked",
                     server == 1, "device blocked on a server",
                     "repeated blocked devices")
| KEEP host_key, subject_user, reason, blocked_devices, classes, devices, device_ids, first_seen, last_seen
```
Run every 15 minutes with a 1-hour lookback. `SubjectUserName` is often the machine account (`HOST$`), because Plug and Play installs as SYSTEM. In that case, the person at the keyboard comes from the logon session at that time, not from this event.

## Suppression
Suppress by `host_key`, `subject_user` for 12h. Alerts missing a key field are not suppressed. Users retry the same blocked device several times, and the device driver retries too.

## Known false positives / exclusions
- **New approved hardware** (a new standard dock or headset model) before it has been added to the allow list. Expect a cluster across many hosts with the same `device_ids`. Fix the allow list rather than excluding here.
- **Phones being charged** from a server's USB port in a datacentre (WPD on a server). It's still a policy breach, but low risk.

## Triage
- **Network adapter or keyboard blocked:** treat it as an attempted hardware attack until explained. Find who was at the machine (logon events, badge records), and look for DV02 or DV03 on the same host.
- **Repeated blocks:** look at `devices`. A mix of storage, phone and network devices suggests someone looking for a way out with data. Check DV01 and the insider rules (IN01, IN05) for the same user.

## Test
With a restriction policy that blocks a test device's hardware ID, plug the device into a lab host and confirm the 6423 event arrives with its `ClassId`.
