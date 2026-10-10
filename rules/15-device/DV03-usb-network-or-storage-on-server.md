---
id: DV03
name: USB or Bluetooth network adapter, storage or phone connected to a server or domain controller
category: device
status: todo
severity: high
rank: 2
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1200, T1052.001, T1011]
data_source: Windows Security 6416 (new external device recognised)
suppression:
  fields: [host_key]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Servers, and domain controllers above all, live in racks or as VMs. Nobody plugs a USB stick, a phone, a USB Ethernet or LTE dongle, or a Bluetooth adapter into them as part of normal work. A USB network adapter on a server is a classic way to bridge a segmented network or get around egress controls. A USB disk is a way to boot tools or carry data out. A phone is both.

The rule keeps only devices whose ID shows they arrived over **USB or Bluetooth**. New virtual disks and virtual NICs, which hypervisors add all the time, never match. They enumerate under SCSI, VMBus or PCI IDs, not USB.

## Prerequisite
- **Audit PNP Activity** (Advanced Audit Policy > Detailed Tracking) set to Success on servers through the server or domain controller GPO.
- Server detection uses `host.os.name`, which the Elastic Agent sets on the host it runs on. If you collect with **Windows Event Forwarding**, `host.*` describes the collector. Replace the server test with your server naming pattern on `host_key`, or a list of domain controllers.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "6416"
| EVAL cls = TO_LOWER(COALESCE(winlog.event_data.ClassName, "")),
       dev = TO_LOWER(COALESCE(device.id, "")),
       host_key = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), "."))),
       os = TO_LOWER(COALESCE(host.os.name, ""))
| WHERE os LIKE "*server*"
  AND cls IN ("net", "diskdrive", "scsiadapter", "wpd", "bluetooth", "modem", "cdrom", "volume", "smartcardreader")
  AND (dev LIKE """usb\\*""" OR dev LIKE "*usbstor*" OR dev LIKE """bth*""" OR dev LIKE """swd\\wpdbusenum\\*""")
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), classes = VALUES(cls),
        devices = VALUES(device.model.name), device_ids = VALUES(device.id),
        users = VALUES(winlog.event_data.SubjectUserName)
    BY host_key, os
| KEEP host_key, os, first_seen, last_seen, classes, devices, device_ids, users
```
Run every 10 minutes with a 30-minute lookback. One insertion creates several devices (the USB device, the disk, the volume), so the query rolls them up into one alert per server.

`Volume` and `CDROM` are included because a USB stick also creates a volume (its ID contains `USBSTOR#`), and some USB devices present a virtual CD with drivers or tools. `SCSIAdapter` catches fast USB SSDs, which attach as USB Attached SCSI (UAS): the adapter has a `USB\` ID even though the disk behind it shows a `SCSI\` one.

## Suppression
Suppress by `host_key` for 6h. Alerts missing a key field are not suppressed. A server that just had a device plugged in is already under investigation, so further insertions in the same window are covered by the first alert.

## Known false positives / exclusions
- **Licence dongles and HSM or token readers** on specific application servers. They are usually `hidclass` or `usb` class, which the rule doesn't watch. If one shows up as `smartcardreader`, exclude that device ID on that host.
- **Physical servers being built** with a USB installer. Exclude hosts while their build ticket is open.
- **USB passthrough to a VM** (a dongle mapped through vSphere or Hyper-V). It looks exactly like a real insertion. Confirm with the virtualisation team, then exclude that device ID in the WHERE.

## Triage
- Domain controller: page immediately. Find who had console access (datacentre access logs, the hypervisor console audit, iLO/iDRAC logs) at `@timestamp`.
- Network adapter: check the server's FDR network events for traffic leaving through a new interface or to an address outside your ranges.
- Storage: check DV01 and FDR for files written to the new disk and for any process started from it.

## Test
On a lab server with PNP auditing on, insert a USB stick and confirm the 6416 events arrive with a `USBSTOR\` device ID.
