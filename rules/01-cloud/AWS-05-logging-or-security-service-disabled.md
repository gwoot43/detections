---
id: AWS-05
name: AWS logging or security service disabled - CloudTrail stopped, GuardDuty removed or muted, Config or flow logs deleted
category: cloud
status: todo
language: esql
index: logs-aws.cloudtrail-*
mitre: [T1562.008, T1562.001]
data_source: AWS CloudTrail management events (Elastic AWS integration)
suppression:
  fields: [aws.cloudtrail.user_identity.arn, finding]
  duration: 24h
  missing_fields: do_not_suppress
---

**Not collected in this estate yet.** CloudTrail is not ingested. Run the probe in `AWS-02` first.

The cloud half of item 17. Before acting in an account, a careful attacker turns off what would record it. Each of
these is one API call, and none is part of routine operation:

| `finding` | Event(s) | Tier |
|---|---|---|
| `cloudtrail_stopped_or_deleted` | `StopLogging`, `DeleteTrail` | alert |
| `cloudtrail_reconfigured` | `UpdateTrail`, `PutEventSelectors` (narrowing what is logged) | risk |
| `guardduty_removed` | `DeleteDetector`, `DisassociateFromMasterAccount`, `DisassociateFromAdministratorAccount` | alert |
| `guardduty_disabled` | `UpdateDetector` with `enable=false` | alert |
| `guardduty_findings_auto_archived` | `CreateFilter` / `UpdateFilter` with action `ARCHIVE` | alert |
| `config_recording_stopped` | `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel` | alert |
| `vpc_flow_logs_deleted` | `DeleteFlowLogs` | alert |
| `security_hub_disabled` | `DisableSecurityHub`, `BatchDisableStandards` | alert |

The GuardDuty archive filter is worth singling out. It leaves GuardDuty running and healthy on every dashboard, while
silently auto-archiving the findings the attacker expects to generate.

The Azure equivalent is `C09`, and the endpoint equivalents are `W05`, `CS05` and `CP06`.

## Query

Run every 5 minutes with a 10-minute lookback.

```esql
FROM logs-aws.cloudtrail-* METADATA _id, _index, _version
| WHERE event.outcome == "success"
  AND event.action IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector",
                       "DisassociateFromMasterAccount", "DisassociateFromAdministratorAccount", "UpdateDetector",
                       "CreateFilter", "UpdateFilter", "StopConfigurationRecorder", "DeleteConfigurationRecorder",
                       "DeleteDeliveryChannel", "DeleteFlowLogs", "DisableSecurityHub", "BatchDisableStandards")
| EVAL params = TO_LOWER(COALESCE(TO_STRING(aws.cloudtrail.request_parameters), ""))
| EVAL finding = CASE(
         event.action IN ("StopLogging", "DeleteTrail"), "cloudtrail_stopped_or_deleted",
         event.action IN ("UpdateTrail", "PutEventSelectors"), "cloudtrail_reconfigured",
         event.action IN ("DeleteDetector", "DisassociateFromMasterAccount", "DisassociateFromAdministratorAccount"),
           "guardduty_removed",
         event.action == "UpdateDetector" AND (params LIKE "*enable=false*" OR params LIKE """*"enable":false*"""),
           "guardduty_disabled",
         event.action IN ("CreateFilter", "UpdateFilter") AND event.provider == "guardduty.amazonaws.com"
           AND params LIKE "*archive*", "guardduty_findings_auto_archived",
         event.action IN ("StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel"),
           "config_recording_stopped",
         event.action == "DeleteFlowLogs", "vpc_flow_logs_deleted",
         event.action IN ("DisableSecurityHub", "BatchDisableStandards"), "security_hub_disabled")
| WHERE finding IS NOT NULL
| EVAL tier = CASE(finding == "cloudtrail_reconfigured", "risk", "alert")
| KEEP @timestamp, tier, finding, event.action, event.provider, aws.cloudtrail.user_identity.arn,
       aws.cloudtrail.recipient_account_id, aws.region, source.ip, user_agent.original, params, _id, _version, _index
```

## Before turning it on

- **Ship CloudTrail from an organisation trail into a separate log-archive account.** A `StopLogging` in a member
  account cannot stop an organisation trail. So the event that stops a local trail is still delivered, and this rule
  can see its own attack.
- **IaC teardown.** Destroying a test environment deletes its flow logs and recorders. Exclude the pair of the
  pipeline role and the sandbox account IDs, never the event type.

## What it misses

- **The trail's S3 bucket emptied or its lifecycle shortened.** That is `DeleteObject` (a data event) or
  `PutBucketLifecycle` on the trail bucket. Add the latter, scoped to the trail bucket's name.
- **CloudWatch Logs groups deleted** (`DeleteLogGroup`), when those are where logs are read from.
- **Silence**, as opposed to a disable call. An organisation trail that stops arriving in Elastic is `CP07`.

## When it fires

Re-enable first. `StartLogging`, re-creating the detector or recorder, and removing the archive filter are all one
call each. Then read everything the same `user_identity.arn` did before and after, using the organisation trail.
