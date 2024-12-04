# aws-third-party-access
Scripts for managing AWS access for vendors, contractors, and other unsavory characters
TestXAccountAccess
TestXAccountApiAccessRole
615299773874
AWSReservedSSO_AWSPowerUserAccess_1f1e013186f96496/bpietravalle
arn:aws:iam::
727426342322
:role/
TestXAccountAccess
arn:aws:iam::<YOUR_ACCOUNT_ID>:role/aws-reserved/sso.amazonaws.com/<REGION>/<UUID>/AWSReservedSSO_<PermissionSetName>_<UUID>

## step 1
1. create EntryRole with Root account access
2. create EntryRole with SSO
3. create Assumed role with external id
4. create Assumed Role without external id
5. Limit Resource actions by Tags, etc.

## Default Scenarios Needed
1. use tf backend
2. create tf backend
3. create secrets (condition by secrets prefix) and SSM (condition by path name)

4. 


https://signin.aws.amazon.com/switchrole?roleName=${RoleName}&account=${Account_id}
