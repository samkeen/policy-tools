import pytest

from policytools.action_request_analyzer import ActionRequestAnalyzer
from policytools.lib.policy_gen_actions_master import PolicyGenActionsMaster
from tests.utils import get_fixture


@pytest.fixture
def action_request_analyzer():
    """
    :return:
    :rtype: ActionRequestAnalyzer
    """
    all_actions_source_data = get_fixture('policies-gen.json.js')
    all_resource_actions = PolicyGenActionsMaster(all_actions_source_data)
    return ActionRequestAnalyzer(all_resource_actions.actions_list())


def test_expand_expect_no_expansion(action_request_analyzer):
    expansion = action_request_analyzer.expand('s3:ListX*')
    assert expansion == ['s3:ListX*'], 'We expect no expansion since "s3:ListX*" should not match'
    expansion = action_request_analyzer.expand('s3:Li*tX*')
    assert expansion == ['s3:Li*tX*'], 'We expect no expansion since "s3:Li*tX" should not match'
    expansion = action_request_analyzer.expand('s3:*XX*')
    assert expansion == ['s3:*XX*'], 'We expect no expansion since "s3:*XX*" should not match'


def test_expand_single_resource(action_request_analyzer):
    expected = {'s3:ListAllMyBuckets', 's3:ListBucketMultipartUploads', 's3:ListBucket', 's3:ListBucketVersions',
                's3:ListBucketByTags', 's3:ListMultipartUploadParts'}
    expansion = action_request_analyzer.expand('s3:List*')
    assert expansion == expected, 'We expect the expanded list of S3 "List" actions'
    expansion = action_request_analyzer.expand('s3:L*st*')
    assert expansion == expected, 'We expect the expanded list of S3 "List" actions'


def test_expand_single_resource_case_insensitive(action_request_analyzer):
    expected = {'s3:ListAllMyBuckets', 's3:ListBucketMultipartUploads', 's3:ListBucket', 's3:ListBucketVersions',
                's3:ListBucketByTags', 's3:ListMultipartUploadParts'}
    expansion = action_request_analyzer.expand('S3:LIST*')
    assert expansion == expected, 'We expect the all UPPERCASE [S3:LIST*] expanded list of S3 "List" actions'
    expansion = action_request_analyzer.expand('S3:LiSt*')
    assert expansion == expected, 'We expect the mixed case [S3:LiSt*] expanded list of S3 "List" actions'
    expansion = action_request_analyzer.expand('s3:list*')
    assert expansion == expected, 'We expect the all lowercase [s3:list*] expanded list of S3 "List" actions'


def test_expand_multi_splat(action_request_analyzer):
    expected = {'s3:ListAllMyBuckets'}
    expansion = action_request_analyzer.expand('s3:List*My*')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:List*My*"'
    expansion = action_request_analyzer.expand('s3:*All*Buckets')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:*All*Buckets"'
    expansion = action_request_analyzer.expand('s3:L*tAllMyBu*ets')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:L*tAllMyBu*ets"'
    expansion = action_request_analyzer.expand('s3:*AllMy*X')
    assert expansion == ['s3:*AllMy*X'], 'We do NOT expect "s3:ListAllMyBuckets" to be matched by "s3:*AllMy*X"'


def test_match_all_actions_for_just_splat():
    all_actions_source_data = get_fixture('policies-gen.json.js')
    all_resource_actions = PolicyGenActionsMaster(all_actions_source_data)
    expected = all_resource_actions.all_actions_for_resource('ec2')
    expander = ActionRequestAnalyzer(all_resource_actions.actions_list())
    expansion = expander.expand('ec2:*')
    assert expansion == expected, 'We expect all the EC2 actions to be matched by "ec2:*"'


def test_expected_denied_action(action_request_analyzer):
    """

    :param action_request_analyzer:
    :type action_request_analyzer: ActionRequestAnalyzer
    :return:
    :rtype:
    """
    expected = {
        "lambda:AddLayerVersionPermission",
        "lambda:AddPermission",
        "lambda:CreateAlias",
        "lambda:CreateEventSourceMapping",
        "lambda:CreateFunction",
        "lambda:DeleteAlias",
        "lambda:DeleteEventSourceMapping",
        "lambda:DeleteFunction",
        "lambda:DeleteFunctionConcurrency",
        "lambda:DeleteLayerVersion",
        "lambda:EnableReplication",
        "lambda:InvokeAsync",
        "lambda:InvokeFunction",
        "lambda:PublishLayerVersion",
        "lambda:PublishVersion",
        "lambda:PutFunctionConcurrency",
        "lambda:RemoveLayerVersionPermission",
        "lambda:RemovePermission",
        "lambda:TagResource",
        "lambda:UntagResource",
        "lambda:UpdateAlias",
        "lambda:UpdateEventSourceMapping",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration"
    }
    # request is for All of lambda
    lambda_all_expansion = action_request_analyzer.expand('lambda:*')
    lambda_read_only_expansion = action_request_analyzer.expand(
        'lambda:List*').union(action_request_analyzer.expand('lambda:Get*'))
    # policy allows only lambda read only
    denied_actions = action_request_analyzer.denied_actions(lambda_read_only_expansion, lambda_all_expansion)
    assert denied_actions == expected, 'We expect to be denied on all Lambda write actions'


def test_expected_denied_action_case_preserve_and_insensitive(action_request_analyzer):
    """

    :param action_request_analyzer:
    :type action_request_analyzer: ActionRequestAnalyzer
    :return:
    :rtype:
    """
    expected = {
        "lambda:AddLayerVersionPermission",
        "LAMBDA:ADDPERMISSION", # up-case one of the allowed actions
        "lambda:CreateAlias",
        "lambda:CreateEventSourceMapping",
        "lambda:CreateFunction",
        "lambda:DeleteAlias",
        "lambda:DeleteEventSourceMapping",
        "lambda:DeleteFunction",
        "lambda:DeleteFunctionConcurrency",
        "lambda:DeleteLayerVersion",
        "lambda:EnableReplication",
        "lambda:InvokeAsync",
        "lambda:InvokeFunction",
        "lambda:PublishLayerVersion",
        "lambda:PublishVersion",
        "lambda:PutFunctionConcurrency",
        "lambda:RemoveLayerVersionPermission",
        "lambda:RemovePermission",
        "lambda:TagResource",
        "lambda:UntagResource",
        "lambda:UpdateAlias",
        "lambda:UpdateEventSourceMapping",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration"
    }
    # request is for All of lambda
    lambda_all_expansion = action_request_analyzer.expand('lambda:*')
    # up-case one of the allowed actions
    lambda_all_expansion.remove('lambda:AddPermission')
    lambda_all_expansion.add('LAMBDA:ADDPERMISSION')
    # mix the case of the requested actions
    lambda_read_only_expansion = action_request_analyzer.expand('LAMBDA:LIST*').union(
        action_request_analyzer.expand('lambda:get*'))
    # policy allows only lambda read only
    denied_actions = action_request_analyzer.denied_actions(lambda_read_only_expansion, lambda_all_expansion)
    assert denied_actions == expected, 'We expect to be denied on all Lambda write actions'
