# Approval authorization configuration

Approval decisions require named principals on both sides of the workflow.

Configure every requester and approver credential as an explicit `identity=secret`
entry. Multiple entries are comma-separated:

```sh
AGENT_API_KEYS="automation=<requester-secret>,operator=<operator-requester-secret>"
AGENT_APPROVER_KEYS="reviewer=<approver-secret>,operator=<operator-approver-secret>"
```

Use a different secret for each role. The identity is the stable principal name:
when the same person has both requester and approver credentials, use the same
identity in both variables. The approval transition then rejects that person's
attempt to approve or deny their own request.

Legacy bare requester secrets remain valid for ordinary API authentication, but
they do not provide enough identity information to safely enable approval
decisions. Legacy bare approver secrets are not accepted. Until both variables
contain valid explicit identities, approver authorization fails closed.

Secrets must be ASCII because the service receives credentials in HTTP headers
and compares them using constant-time string comparison. Do not commit real
secrets to the repository; configure them through the deployment environment
or a secret manager.
