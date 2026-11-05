# Analyst triage

A suite hit is a correlation hypothesis, not a verdict. Preserve source IDs and UTC event times. Review native Entra/Defender incidents first and attach useful new evidence to the existing investigation rather than opening duplicate work.

## S001: device-code authentication → method registration

1. Confirm both source events succeeded and refer to the same **directory and target object ID**. Check the registration actor separately; it can differ from the user.
2. Establish whether device-code use and registration were expected onboarding, approved tooling or a helpdesk workflow. A successful device-code grant is not intrinsically malicious.
3. Review actual method changes and registration origin in authoritative Entra records. The registration operation does not by itself prove an attacker controls the method.
4. Inspect native token/phishing/credential-addition risks and subsequent workload activity. IP changes are context, not proof of session theft; the rule does not establish token continuity.
5. For confirmed compromise, follow your approved containment workflow: session revocation, credential review and removal of unauthorized methods. Recheck access and persistence after containment; a password reset alone is not proof of complete remediation.

## S002: method registration → multi-surface Graph reads

1. Confirm request IDs are distinct, reads succeeded, and one application performed the counted surfaces after the registration.
2. Check approved inventory, search, collaboration and onboarding applications. Review the user/application combination and business context before treating enumeration as hostile.
3. Pivot to actual Graph request paths, available session/sign-in linkage and workload audit events. Do not assume requests from different IPs belong to separate actors, or that a common user alone proves one session.
4. Distinguish directory discovery, content-oriented requests, recorded downloads and independently verified exfiltration. The rule proves only the first correlation; `/sites` access is not a file download.
5. Investigate unexpected application authorizations, account changes or collection using appropriate native tooling. Application-only Graph calls are outside S002's delegated-user scope.

## S003 / D001: native risk → method evidence

1. Review why Microsoft assigned the risk, its time of computation, current state and existing incident. This suite enriches that evidence; it does not reproduce Microsoft's risk engine.
2. S003 reports successful individual registration. D001 instead compares old/new phone-app method IDs and requires a self-attributed update. Check for normal authenticator replacement and legitimate device migration, including same-count replacements.
3. Confirm source `Timestamp`, `ReportId` and `AccountObjectId` for D001; do not remediate an actor merely because an unrelated target appears in a raw event. The shipped query rejects actor/target mismatch.
4. Avoid a second alerting route if S003/D001 or a native incident already provide the same investigation value.

## H001: service-principal hunting

Verify continuous history, initiating principal ID, property semantics, actual credential key IDs/thumbprints where available and authorized rotation. First seen in 14 days is not first ever; a new proxy/NAT/cloud address is not compromise. Metadata changes include removal and rotation. Application-object changes are not mapped by this query, and subsequent sign-in does not establish which credential was used. Keep hunting-only until a tenant-specific mapping and validation strategy exist.

## Evidence handling and response

Log output can expose identities, resource paths and sensitive business context. Keep exports in approved storage and apply workspace RBAC. Do not publish query results or credential material. Automatic account disabling, permission removal, token revocation and broad app blocking are deliberately not configured by this package. Follow established incident authority and recovery procedures.
