import pytest

from policytools.action_expander import ActionExpander
from policytools.master_list.policy_gen_actions_master_list import PolicyGenActionsMasterList
from policytools.policy import Policy
from policytools.service_control_policy import ServiceControlPolicy
from tests.utils import get_fixture


@pytest.fixture
def action_expander():
    """
    :return:
    :rtype: ActionExpander
    """
    all_actions_source_data = get_fixture('policies-gen.json.js')
    return ActionExpander(PolicyGenActionsMasterList(all_actions_source_data))


def test_implicit_deny(action_expander):
    # user is asking for all of sts
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSts",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            }
        ]
    }""", action_expander)
    # The SCP is allowing all of S3.  sts is not mentioned so it is implicitly denied
    scp = ServiceControlPolicy("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowS3",
                    "Effect": "Allow",
                    "Resource": "*",
                    "Action": [
                        "s3:*"
                    ]
                }
            ]
        }""", action_expander)

    result = scp.effect_on(user_policy)

    assert result.denied_actions == {
        'sts:DecodeAuthorizationMessage', 'sts:AssumeRole', 'sts:GetCallerIdentity',
        'sts:AssumeRoleWithWebIdentity', 'sts:AssumeRoleWithSAML',
        'sts:GetFederationToken'}, \
        'We expect all off the sts actions to be implicitly denied'


def test_implicit_deny_case_insensitive(action_expander):
    # user is asking for all of sts
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSts",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "STS:*"
                ]
            }
        ]
    }""", action_expander)
    # The SCP is allowing all of S3.  sts is not mentioned so it is implicitly denied
    scp = ServiceControlPolicy("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowS3",
                    "Effect": "Allow",
                    "Resource": "*",
                    "Action": [
                        "S3:*"
                    ]
                }
            ]
        }""", action_expander)

    result = scp.effect_on(user_policy)

    assert result.denied_actions == {
        'sts:DecodeAuthorizationMessage', 'sts:AssumeRole', 'sts:GetCallerIdentity',
        'sts:AssumeRoleWithWebIdentity', 'sts:AssumeRoleWithSAML',
        'sts:GetFederationToken'}, \
        'We expect all off the sts actions to be implicitly denied'


def test_implicit_deny_allow_mix(action_expander):
    # user is asking for all of sts and all of sqs
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
    # The SCP is allowing "read only" on s3 and sqs
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

    result = scp.effect_on(user_policy)

    assert result.denied_actions == {'sqs:SetQueueAttributes',
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
                                     'elastictranscoder:UpdatePipeline'}, \
        'We expect all off the sts actions to be implicitly denied'
