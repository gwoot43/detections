---
id: AWS-04
name: AWS S3 bucket exposed - public policy or ACL, Block Public Access removed, or a bucket-enumeration burst
category: cloud
status: todo
language: esql
index: logs-aws.cloudtrail-*
mitre: [T1530, T1537]
data_source: AWS CloudTrail management events, S3 (Elastic AWS integration)
suppression:
  fields: [aws.cloudtrail.user_identity.arn, finding]
  duration: 24h
  missing_fields: do_not_suppress
---

**Not collected in this estate yet.** CloudTrail is not ingested. Run the probe in `AWS-02` first.

Two halves, matching the item's two signals.

1. **Exposure (alert grade).** One configuration call makes a bucket readable by anyone: a bucket policy whose
   `Principal` is `*`, an ACL granting `AllUsers` or `AuthenticatedUsers`, or Block Public Access removed or weakened
   on the bucket. These are rare in a well-run account and reviewable every time.
2. **Enumeration (risk grade).** A principal calling `ListBuckets` and then reading the policy, ACL or location of
   many buckets in a short window. This is the reconnaissance that precedes collection. It uses management events,
   which are logged by default.

`GetObject` volume, the actual data theft, is an S3 **data event**. Data events are off by default and expensive,
so it is not part of this rule. See "What it misses".

## Query 1 — a bucket made public

Run every 15 minutes with a 20-minute lookback.

```esql
FROM logs-aws.cloudtrail-* METADATA _id, _index, _version
| WHERE event.provider == "s3.amazonaws.com"
  AND event.outcome == "success"
  AND event.action IN ("PutBucketPolicy", "PutBucketAcl", "PutObjectAcl", "DeleteBucketPublicAccessBlock",
                       "PutBucketPublicAccessBlock", "PutBucketWebsite")
| EVAL params = COALESCE(TO_STRING(aws.cloudtrail.request_parameters), "")
// Principal of * (bare, as {AWS=*}, or in JSON with escaped quotes)
| GROK params """(?<public_principal>Principal\\?"?\s{0,4}[:=]\s{0,4}(\{\s{0,4}\\?"?AWS\\?"?\s{0,4}[:=]\s{0,4})?\[?\s{0,4}\\?"?\*)"""
| GROK params """(?<public_acl>AllUsers|AuthenticatedUsers|public-read-write|public-read)"""
| GROK params """(?<bpa_off>(BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)\\?"?\s{0,4}[:=]\s{0,4}false)"""
| GROK params """bucketName=(?<bucket>[^,}\s]+)"""
| EVAL finding = CASE(
         event.action == "PutBucketPolicy" AND public_principal IS NOT NULL, "bucket_policy_principal_star",
         event.action IN ("PutBucketAcl", "PutObjectAcl") AND public_acl IS NOT NULL, "public_acl_granted",
         event.action == "DeleteBucketPublicAccessBlock", "block_public_access_removed",
         event.action == "PutBucketPublicAccessBlock" AND bpa_off IS NOT NULL, "block_public_access_weakened",
         event.action == "PutBucketWebsite", "static_website_enabled")
| WHERE finding IS NOT NULL
| KEEP @timestamp, finding, event.action, bucket, aws.cloudtrail.user_identity.arn,
       aws.cloudtrail.recipient_account_id, source.ip, user_agent.original, params, _id, _version, _index
```

A `Principal` of `*` with a `Condition` restricting it to your organisation (`aws:PrincipalOrgID`) or a VPC
endpoint is not public. Read `params` before escalating, because the condition is the difference.

## Query 2 — bucket enumeration burst

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-aws.cloudtrail-*
| WHERE event.provider == "s3.amazonaws.com"
  AND event.action IN ("ListBuckets", "GetBucketPolicy", "GetBucketAcl", "GetBucketLocation",
                       "GetBucketPolicyStatus", "GetBucketPublicAccessBlock")
| EVAL params = COALESCE(TO_STRING(aws.cloudtrail.request_parameters), "")
| GROK params """bucketName=(?<bucket>[^,}\s]+)"""
| STATS list_calls = COUNT(*) WHERE event.action == "ListBuckets",
        buckets_read = COUNT_DISTINCT(bucket),
        actions = MV_SLICE(VALUES(event.action), 0, 6),
        ips = MV_SLICE(VALUES(TO_STRING(source.ip)), 0, 3),
        asns = MV_SLICE(VALUES(source.as.organization.name), 0, 3),
        agents = MV_SLICE(VALUES(user_agent.original), 0, 3)
    BY aws.cloudtrail.user_identity.arn
// Baseline: a person or app reads the configuration of the few buckets it uses. Listing every bucket and then
// reading the policy or ACL of 20+ is a sweep (ScoutSuite, Pacu, or a stolen key being explored). 20 is a starting
// value; measure the p99 per principal over a week, and exclude CSPM scanners as role-and-account pairs.
| WHERE list_calls >= 1 AND buckets_read >= 20
| SORT buckets_read DESC
| LIMIT 50
```

## Before turning it on

- Account-level Block Public Access (`s3control` `PutPublicAccessBlock`) is a separate event source. If your
  organisation enforces it account-wide, add that event too, because removing it exposes every bucket at once.
- Exclude cloud security posture tools (Wiz, Prisma, Security Hub) from Query 2 as the pair of their role ARN and the
  account. They read every bucket's configuration on a schedule.

## What it misses

- **Data theft itself.** `GetObject` and `ListObjects` are S3 data events. Enable them, at least for the buckets that
  hold sensitive data, and add a third query: `GetObject` volume per principal per hour, against a baseline.
- **Exposure through a presigned URL**, which needs no configuration change.
- **Cross-account replication** to an attacker's bucket (`PutBucketReplication`). Worth adding if replication is
  rare in your accounts.

## When it fires

For exposure: revert first (restore Block Public Access, remove the policy statement), then read S3 server access
logs or data events for reads from outside your accounts since `@timestamp`. For enumeration: treat the principal's
credentials as stolen until shown otherwise.
