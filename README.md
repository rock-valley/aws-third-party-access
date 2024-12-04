# aws-third-party-access
Scripts for managing AWS access for vendors, contractors, and other unsavory characters.

This library creates two cross-account roles for your AWS account. This simplifies giving a third party (e.g., a contractor) limited access to your account via their own AWS account. 

### Why two roles?
This library provides a role for Console access and a role for API access. The difference is that the API access role requires `external-id` in the STS call.  `external-id` is not supported in the console, thus two roles are required.

## How to Use:
- set `.env.` file
- create resource_policies for each role - these 
- create statements
- create policies
- create roles
- attach policies

### setting the `.env` file
Setting the env file requires some values from the contractor and some values set by you.
```

```
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

### How will vendor use
For console access:
1. Login to their AWS account
2. Navigate to: https://signin.aws.amazon.com/switchrole?roleName=${RoleName}&account=${Account_id}

For API Access, add something like the following to `~/.aws/config`
```ini
[profile vendor_account]
region = us-east-1
output = json
aws_access_key_id = example
aws_secret_access_key = example

[profile api_access]
region = us-east-1
output = json
role_arn = arn:aws:iam::{aws_account_id}:role/{api_access_role_name}
source_profile = vendor_account
external_id = foo
role_session_name = bar
```

Then vendor can simple call `aws --profile api_access` or use `api_access` in terraform projects.


### Resources

- [Configuring your CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html )
