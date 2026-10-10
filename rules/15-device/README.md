# Device and hardware detections

Detections for physical access and hardware: keystroke-injection devices, USB network adapters or storage on servers, bulk copying to USB, boot settings that let unsigned drivers load, and attempts to get past device-control policy. These are the paths a red team or an insider with physical access uses, and none of the network or identity rules can see them.

## Ranked by criticality

| Rank | Rule | Behaviour | Source |
|---|---|---|---|
| 1 | DV02 | New keyboard device, then a shell launched from Explorer within 90 seconds (Rubber Ducky, O.MG, BadUSB) | 6416 + FDR |
| 2 | DV03 | USB or Bluetooth network adapter, storage or phone connected to a server or DC | 6416 |
| 2 | DV04 | Boot integrity weakened: test signing, integrity checks off, kernel debugging (bcdedit, or seen at boot) | 4826 + FDR |
| 3 | DV01 | Bulk copy of documents or archives to removable media | FDR (or 4663) |
| 4 | DV05 | Device installation blocked by policy (network, keyboard, server, repeated) | 6423 |

## Prerequisites

| Setting | Where | Needed by |
|---|---|---|
| Audit PNP Activity: Success | Advanced Audit Policy > Detailed Tracking (workstations and servers) | DV02, DV03, DV05 |
| Audit Other Policy Change Events: Success | Advanced Audit Policy > Policy Change | DV04 (4826) |
| Audit Removable Storage: Success | Advanced Audit Policy > Object Access | DV01 option B only |
| Device Installation Restrictions policy | GPO or Intune Device Control | DV05 |

PNP auditing is low volume: 6416 only fires the first time a device instance is seen on a host. Removable Storage auditing logs every file touched on USB media and is noisy, which is why DV01 uses Falcon by default.

All five rules match hosts on `winlog.computer_name` (short name, lowercase) rather than `host.name`. With Windows Event Forwarding, `host.name` is the collector, not the machine the event came from.

## What Falcon can add

Falcon records USB and device activity in FDR, but which events carry device fields depends on your sensor version and on whether Device Control is licensed. Run this once to see what your feed has:

```esql
FROM logs-crowdstrike.fdr-*
| WHERE crowdstrike.DeviceInstanceId IS NOT NULL OR crowdstrike.IsOnRemovableDisk IN ("1", "true")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.id) BY event.action
| SORT events DESC
```

If Device Control events (for example `DcUsbDeviceConnected`) appear, DV02 and DV03 can be rewritten against FDR alone, with no Windows auditing needed.

## Considered and not built

- **USB devices on workstations generally.** Too common to alert on. DV05 covers the policy-violating ones.
- **BitLocker suspended or turned off.** It's a tamper signal, but routine during patching and firmware updates (`manage-bde -protectors -disable` with a reboot count). Better as a dashboard of hosts suspended for more than one reboot.
- **Kernel DMA (Thunderbolt) attacks.** No reliable event on current builds. Mitigate with Kernel DMA Protection and BIOS settings, not detection.
- **Mounting a VHD or ISO and running from it.** Already covered by W12.
- **Code Integrity blocks (3033, 3077).** These depend heavily on WDAC policy. Revisit once you deploy WDAC or Smart App Control.
