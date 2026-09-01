# FlowCrypid privacy and data handling

PCAP files may contain credentials, personal information, internal addresses, hostnames, URLs, and payload data. Treat every capture as sensitive unless its owner has explicitly classified it otherwise.

## Collection and access

Only collect captures required for the investigation. Record the capture owner, source environment, collection time, purpose, and approved retention period. Limit upload and capture-history access to authenticated analysts and administrators. Do not place PCAP files in the public web root or commit them to source control.

## Redaction mode

For demonstrations or shared screenshots, set:

```bash
FLOWCRYPID_PRIVACY_MODE=redact
```

In redaction mode, returned IPv4 addresses are reduced to a network-level prefix and IPv6 values are shortened. This affects API finding responses; it does not make the original PCAP safe to share. The original capture must still be protected, retained only when justified, and deleted according to policy.

## Storage and logs

Keep the SQLite database and any future object storage on encrypted volumes with least-privilege access. Use the default application logs for operational metadata only. Never log passwords, bearer tokens, authorization headers, raw packet payloads, or full finding payloads. Review reverse-proxy logs because request paths and status codes may still reveal operational context.

## Retention and deletion

Configure the smallest practical retention period:

```bash
FLOWCRYPID_RETENTION_DAYS=30
```

Retention cleanup removes expired sessions and capture records older than the configured threshold, with findings removed through the database foreign-key relationship. Before reducing retention, create an approved backup if the records may be needed for an investigation. Verify deletion in the database and in backups according to the organization’s deletion policy.

## Sharing and exports

CSV exports include finding evidence, explanation text, and calibration metadata. Treat exports as sensitive. Share only with authorized recipients, use encrypted transfer, and delete temporary copies. Before publishing screenshots or reports, redact IP addresses, usernames, hostnames, tokens, URLs, and timestamps that could identify an environment.

## Privacy incident response

If a capture or export is sent to the wrong person, preserve the relevant audit context, revoke active sessions if necessary, notify the data owner, request deletion from all recipients and storage locations, and document the scope. Do not attempt to conceal the event by deleting logs or overwriting the original database.

## Deployment checklist

| Control | Required action |
|---|---|
| Credentials | Replace seeded local credentials and use a secret manager outside local demos. |
| Encryption | Encrypt storage, backups, and network traffic. |
| Access | Restrict API, database, metrics, and backup access. |
| Redaction | Enable privacy mode for demonstrations and shared outputs. |
| Retention | Set and review `FLOWCRYPID_RETENTION_DAYS`. |
| Backups | Encrypt backups and restrict their separate access path. |
| Logging | Confirm secrets and packet payloads are absent from logs. |
