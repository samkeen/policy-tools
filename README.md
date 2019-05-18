# policy-tools

[![CircleCI](https://circleci.com/gh/samkeen/policy-tools.svg?style=svg)](https://circleci.com/gh/samkeen/policy-tools)

[![codecov](https://codecov.io/gh/samkeen/policy-tools/branch/master/graph/badge.svg)](https://codecov.io/gh/samkeen/policy-tools)

[![Requirements Status](https://requires.io/github/samkeen/policy-tools/requirements.svg?branch=master)](https://requires.io/github/samkeen/policy-tools/requirements/?branch=master)

## Summary

This is a utility to programmatically determine the effect of an AWS Organizations 
[Service Control Policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html) 
on a given user policy.

## Usage

```python
# create you "All IAM actions" set
with open('policies-gen.json.js') as file_stream:
    all_actions_source_data = file_stream.read()
# create your ActionExpander utility (it simply expands glob statements 's3:*' into the full matched set of IAM actions)
policy_actions_expander = ActionExpander(PolicyGenActionsMasterList(all_actions_source_data))

# create the user policy
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
    
# create the service control policy
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
        
# Determine the effect of the SCP on the user policy
result = scp.effect_on(user_policy)

# result is
#  {  'sqs:SetQueueAttributes',
#     'sqs:PurgeQueue',
#     'sqs:DeleteMessageBatch',
#     'sqs:ReceiveMessage',
#     'sqs:RemovePermission',
#     'sqs:ChangeMessageVisibilityBatch',
#     'sqs:SendMessageBatch',
#     'sqs:CreateQueue',
#     'sqs:TagQueue',
#     'sqs:AddPermission',
#     'sqs:UntagQueue',
#     'sqs:SendMessage',
#     'sqs:DeleteMessage',
#     'sqs:ChangeMessageVisibility',
#     'sqs:DeleteQueue',
#     'elastictranscoder:TestRole',
#     'elastictranscoder:CreatePipeline',
#     'elastictranscoder:DeletePipeline',
#     'elastictranscoder:UpdatePipelineNotifications',
#     'elastictranscoder:DeletePreset',
#     'elastictranscoder:CancelJob',
#     'elastictranscoder:CreateJob',
#     'elastictranscoder:UpdatePipelineStatus',
#     'elastictranscoder:CreatePreset',
#     'elastictranscoder:UpdatePipeline'
#  }
 
```