import pytest

from policytools.action_expander import ActionExpander
from policytools.master_list.policy_gen_actions_master_list import PolicyGenActionsMasterList
from policytools.policy import Policy
from tests.utils import get_fixture


@pytest.fixture
def action_expander():
    """
    :return:
    :rtype: ActionExpander
    """
    all_actions_source_data = get_fixture('policies-gen.json.js')
    return ActionExpander(PolicyGenActionsMasterList(all_actions_source_data))


def test_allowed_actions_raw(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allowlist1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "AllowlistTestingDupeIsIgnored",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "Allowlist3",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "s3:Get*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.allow_actions_raw == {'sts:*', 's3:Get*'}


def test_allowed_actions_raw_case_preserve_and_insensitive(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allowlist1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "AllowlistTestingDupeIsIgnored",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "Allowlist3",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "s3:GET*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.allow_actions_raw == {'sts:*', 's3:GET*'}


def test_allowed_actions_single_allow_stmt(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allowlist1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.allowed_actions == {
        # full list of sts actions
        'sts:GetCallerIdentity',
        'sts:GetFederationToken',
        'sts:DecodeAuthorizationMessage',
        'sts:AssumeRoleWithSAML',
        'sts:AssumeRole',
        'sts:AssumeRoleWithWebIdentity'
    }


def test_allowed_actions_allow_with_explict_deny(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "Deny1",
                "Effect": "Deny",
                "Resource": "*",
                "Action": [
                    "sts:Assume*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.allowed_actions == {
        # full list of sts actions
        'sts:GetCallerIdentity',
        'sts:GetFederationToken',
        'sts:DecodeAuthorizationMessage'
    }


def test_deny_actions_raw(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "Deny1",
                "Effect": "Deny",
                "Resource": "*",
                "Action": [
                    "sts:Assume*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.deny_actions_raw == {'sts:Assume*'}, \
        'We expect the deny actions returned unaltered'


def test_deny_actions_raw_case_preserved(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "Deny1",
                "Effect": "Deny",
                "Resource": "*",
                "Action": [
                    "sts:ASSUME*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.deny_actions_raw == {'sts:ASSUME*'}, \
        'We expect the deny actions returned unaltered and the case to be preserved'


def test_denied_actions_explicit(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "Deny1",
                "Effect": "Deny",
                "Resource": "*",
                "Action": [
                    "sts:Assume*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.denied_actions_explicit == {
        'sts:AssumeRole',
        'sts:AssumeRoleWithWebIdentity',
        'sts:AssumeRoleWithSAML'
    }, 'We expect the deny actions returned unaltered and the case to be preserved'


def test_denied_actions_explicit_case_insensitive(action_expander):
    user_policy = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow1",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "Deny1",
                "Effect": "Deny",
                "Resource": "*",
                "Action": [
                    "sts:ASSUME*"
                ]
            }
        ]
    }""", action_expander)
    assert user_policy.denied_actions_explicit == {
        'sts:AssumeRole',
        'sts:AssumeRoleWithWebIdentity',
        'sts:AssumeRoleWithSAML'
    }, 'We expect the deny actions to be accurate when using ASSUME*'


def test_denied_actions_explicit_multiple_statements(action_expander):
    expanded_actions = Policy("""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSts",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "AllowStsTestingDupeIsIgnored",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "sts:*"
                ]
            },
            {
                "Sid": "AllowS3Get",
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "s3:Get*"
                ]
            },
            {
                "Sid": "DenyStsAssume",
                "Effect": "Deny",
                "Resource": "*",
                "Action": [
                    "sts:Assume*"
                ]
            }
        ]
    }""", action_expander)
    assert expanded_actions.allowed_actions == {
        's3:GetAccountPublicAccessBlock',
        's3:GetAccelerateConfiguration',
        's3:GetAnalyticsConfiguration',
        's3:GetBucketAcl',
        's3:GetBucketCORS',
        's3:GetBucketLocation',
        's3:GetBucketLogging',
        's3:GetBucketNotification',
        's3:GetBucketPolicy',
        's3:GetBucketPolicyStatus',
        's3:GetBucketPublicAccessBlock',
        's3:GetBucketRequestPayment',
        's3:GetBucketTagging',
        's3:GetBucketVersioning',
        's3:GetBucketWebsite',
        's3:GetEncryptionConfiguration',
        's3:GetInventoryConfiguration',
        's3:GetLifecycleConfiguration',
        's3:GetMetricsConfiguration',
        's3:GetObject',
        's3:GetObjectAcl',
        's3:GetObjectTagging',
        's3:GetObjectTorrent',
        's3:GetObjectVersion',
        's3:GetObjectVersionAcl',
        's3:GetObjectVersionForReplication',
        's3:GetObjectVersionTagging',
        's3:GetObjectVersionTorrent',
        's3:GetReplicationConfiguration',
        'sts:DecodeAuthorizationMessage',
        'sts:GetCallerIdentity',
        'sts:GetFederationToken'
    }
    assert expanded_actions.denied_actions_explicit == {
        'sts:AssumeRole',
        'sts:AssumeRoleWithSAML',
        'sts:AssumeRoleWithWebIdentity'
    }
# def test_scenario_1(actions_master_list):
#     user_policy = UserPolicy("""{
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Sid": "AllowSts",
#                 "Effect": "Allow",
#                 "Resource": "*",
#                 "Action": [
#                     "sts:*"
#                 ]
#             },
#             {
#                 "Sid": "AllowS3",
#                 "Effect": "Deny",
#                 "Resource": "*",
#                 "Action": [
#                     "s3:*"
#                 ]
#             }
#         ]
#     }""", actions_master_list)
#     # this policy allows the Read permissions of S3.
#     # sts is implicitly denies as it is not listed in this SCP policy
#     scp_policy = UserPolicy("""{
#             "Version": "2012-10-17",
#             "Statement": [
#                 {
#                     "Sid": "AllowS3",
#                     "Effect": "Deny",
#                     "Resource": "*",
#                     "Action": [
#                         "s3:Get*",
#                         "s3:List*",
#                         "s3:Describe*",
#                     ]
#                 }
#             ]
#         }""", actions_master_list)
#     result = scp_policy.effect_on(user_policy)
#
#     assert result.denied_actions == {
#         'sts:',
#         '',
#         ''
#     }
