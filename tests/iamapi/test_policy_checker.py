import json

import pytest

from policytools.iamapi.judged_action import JudgedAction
from policytools.iamapi.policy_checker import PolicyChecker
from policytools.iamapi.check_response import CheckResponse
from tests.iamapi.aws_client_stub import AwsClientStub
from tests.utils import get_json_fixture_as_string


def test_exception_on_invalid_json():
    checker = PolicyChecker(AwsClientStub(''))
    with pytest.raises(json.decoder.JSONDecodeError):
        checker.append_policy('policy_label', '--invalid JSON--')


def test_no_exception_on_valid_json():
    checker = PolicyChecker(AwsClientStub(''))
    checker.append_policy('policy_label', '{"valid":"JSON"}')
    # no exception, so...
    assert True


def test_policy_check_actions_expect_no_denied_actions():
    checker = PolicyChecker(
        AwsClientStub(get_json_fixture_as_string('iamapi/s3-resource/resp.s3.GetObject.allowed.json'))
    )
    deny_putobject_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3.PutObject.deny.json')
    allow_s3_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3-star.allow.json')
    checker.append_policy('iamapi/policy.s3.PutObject.deny.json', deny_putobject_policy)
    checker.append_policy('iamapi/policy.s3-star.allow.json', allow_s3_policy)
    result = checker.check_actions(['s3:GetObject'])
    assert isinstance(result, CheckResponse), 'result was not an instance of CheckResponse'
    assert len(result.denied_actions_all()) == 0, 'there are no denied actions'


def test_policy_check_actions_expect_allowed_action():
    checker = PolicyChecker(
        AwsClientStub(get_json_fixture_as_string('iamapi/s3-resource/resp.s3.GetObject.allowed.json'))
    )
    deny_putobject_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3.PutObject.deny.json')
    allow_s3_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3-star.allow.json')
    checker.append_policy('iamapi/policy.s3.PutObject.deny.json', deny_putobject_policy)
    checker.append_policy('iamapi/policy.s3-star.allow.json', allow_s3_policy)
    result = checker.check_actions(['s3:GetObject'])
    assert len(result.allowed_actions()) == 1, 'there is 1 allowed action'
    action: JudgedAction = result.allowed_actions()[0]
    assert action.action_name == 's3:GetObject', 'the allowed action is "s3:GetObject"'


def test_policy_check_actions_expect_no_allowed_actions():
    checker = PolicyChecker(
        AwsClientStub(get_json_fixture_as_string('iamapi/s3-resource/resp.s3.PutObject.explicitDeny.json'))
    )
    allow_s3_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3-star.allow.json')
    deny_s3_putobject_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3.PutObject.deny.json')
    checker.append_policy('iamapi/policy.s3-star.allow.json', allow_s3_policy)
    checker.append_policy('iamapi/policy.s3.PutObject.deny.json', deny_s3_putobject_policy)
    result = checker.check_actions(['s3:PutObject'])
    assert len(result.allowed_actions()) == 0, 'there is no allowed actions'


def test_policy_check_actions_expect_explicit_denied_action():
    checker = PolicyChecker(
        AwsClientStub(get_json_fixture_as_string('iamapi/s3-resource/resp.s3.PutObject.explicitDeny.json'))
    )
    allow_s3_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3-star.allow.json')
    deny_s3_putobject_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3.PutObject.deny.json')
    checker.append_policy('iamapi/policy.s3-star.allow.json', allow_s3_policy)
    checker.append_policy('iamapi/policy.s3.PutObject.deny.json', deny_s3_putobject_policy)
    result = checker.check_actions(['s3:PutObject'])
    assert len(result.denied_actions_all()) == 1, 'there is 1 denied action'
    assert len(result.allowed_actions()) == 0, 'there should be no allowed action'
    denied_action: JudgedAction = result.denied_actions_all()[0]
    assert denied_action.denial_type == 'explicit', 'the denial should be an explicit one'


def test_policy_check_actions_expect_implicit_denied_action():
    checker = PolicyChecker(
        AwsClientStub(get_json_fixture_as_string('iamapi/s3-resource/resp.ec2.CreateInstance.implicitDeny.json'))
    )
    deny_s3_putobject_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3.PutObject.deny.json')
    checker.append_policy('iamapi/policy.s3.PutObject.deny.json', deny_s3_putobject_policy)
    result = checker.check_actions(['ec2:CreateInstance'])
    assert len(result.denied_actions_all()) == 1, 'there is 1 denied action'
    assert len(result.allowed_actions()) == 0, 'there should be no allowed action'
    denied_action: JudgedAction = result.denied_actions_all()[0]
    assert denied_action.denial_type == 'implicit', 'the denial should be an implicit one'


def test_policy_check_actions_retrieve_judging_stmt_for_explicit_denied_action():
    checker = PolicyChecker(
        AwsClientStub(get_json_fixture_as_string('iamapi/s3-resource/resp.s3.PutObject.explicitDeny.json'))
    )
    allow_s3_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3-star.allow.json')
    deny_s3_putobject_policy = get_json_fixture_as_string('iamapi/s3-resource/policy.s3.PutObject.deny.json')
    checker.append_policy('iamapi/policy.s3-star.allow.json', allow_s3_policy)
    checker.append_policy('iamapi/policy.s3.PutObject.deny.json', deny_s3_putobject_policy)
    result = checker.check_actions(['s3:PutObject'])
    denied_action: JudgedAction = result.denied_actions_all()[0]
    expected_statement = json.loads("""
    {
        "Sid": "DenyList",
        "Effect": "Deny",
        "Resource": "*",
        "Action": [
            "s3:Put*"
        ]
    }""")
    assert len(denied_action.get_decider_statements()) == 1, 'we expect 1 decider policy'
    deciding_policy = denied_action.get_decider_statements()[0]['text']
    assert deciding_policy == json.dumps(expected_statement)
