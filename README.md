# policy-tools

[![CircleCI](https://circleci.com/gh/samkeen/policy-tools.svg?style=svg)](https://circleci.com/gh/samkeen/policy-tools)

[![codecov](https://codecov.io/gh/samkeen/policy-tools/branch/master/graph/badge.svg)](https://codecov.io/gh/samkeen/policy-tools)

[![Requirements Status](https://requires.io/github/samkeen/policy-tools/requirements.svg?branch=master)](https://requires.io/github/samkeen/policy-tools/requirements/?branch=master)

## Summary

This is a utility of helper tools for working with AWS IAM Policies.

Currently it programmatically determine the effect of an AWS Organizations 
[Service Control Policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html) 
on a given user policy.

```python
result = scp.effect_on(user_policy)
print result.denied_actions
```

## Usage

Create your "All IAM actions" set
```python 
# policies-gen.json.js is the content of https://awspolicygen.s3.amazonaws.com/js/policies.js
with open('policies-gen.json.js') as file_stream:
    all_actions_source_data = file_stream.read()
```
Create your ActionExpander utility.  It simply expands *glob* statements (e.g. `s3:*`) into the full matched set of IAM actions.
```python 
policy_actions_expander = ActionExpander(PolicyGenActionsMasterList(all_actions_source_data))
```
Create the user policy and the service control policy
```python
user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSts",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sqs:*"
                ]
            },
            {
                "Sid": "AllowEfs",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "elastictranscoder:*"
                ]
            }
        ]
    }""", action_expander)
    
 scp = ServiceControlPolicy("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowS3Read",
                    "Effect": "Allow",
                    "Resource": "*",
                    "Action": [
                        "sqs:Get*",
                        "sqs:List*"
                    ]
                },
                {
                    "Sid": "AllowElasticTranscoderRead",
                    "Effect": "Allow",
                    "Resource": "*",
                    "Action": [
                        "elastictranscoder:Read*",
                        "elastictranscoder:List*"
                    ]
                }
            ]
        }""", action_expander) 
```
Determine the effect of the SCP on the user policy
```python
result = scp.effect_on(user_policy)
print result.denied_actions

{  'sqs:SetQueueAttributes',
     'sqs:PurgeQueue',
     'sqs:DeleteMessageBatch',
     'sqs:ReceiveMessage',
     'sqs:RemovePermission',
     'sqs:ChangeMessageVisibilityBatch',
     'sqs:SendMessageBatch',
     'sqs:CreateQueue',
     'sqs:TagQueue',
     'sqs:AddPermission',
     'sqs:UntagQueue',
     'sqs:SendMessage',
     'sqs:DeleteMessage',
     'sqs:ChangeMessageVisibility',
     'sqs:DeleteQueue',
     'elastictranscoder:TestRole',
     'elastictranscoder:CreatePipeline',
     'elastictranscoder:DeletePipeline',
     'elastictranscoder:UpdatePipelineNotifications',
     'elastictranscoder:DeletePreset',
     'elastictranscoder:CancelJob',
     'elastictranscoder:CreateJob',
     'elastictranscoder:UpdatePipelineStatus',
     'elastictranscoder:CreatePreset',
     'elastictranscoder:UpdatePipeline'
  }
 
```
 # Developing
 
 **create file ~/.pypirc** (if you do not already have)
```
[distutils]
index-servers =
  pypi
  pypitest

[pypi]
repository: https://upload.pypi.org/legacy/
username:
password:

[pypitest]
repository: https://test.pypi.org/legacy/
username:
password:
```

**build**

Update the version in `policytools/version.txt`
```
rm -rf dist
python setup.py bdist_wheel --universal
```

**pypitest**
```
twine upload --repository pypitest dist/*
pip install policytools --index-url https://test.pypi.org/simple/ --upgrade
```

**pypi**
```
twine upload --repository pypi dist/*
pip install policytools --upgrade
```