import pytest

from policytools.action_expander import ActionExpander
from policytools.master_list.policy_gen_actions_master_list import PolicyGenActionsMasterList
from tests.utils import get_fixture


@pytest.fixture
def action_expander():
    """

    :return:
    :rtype: ActionExpander
    """
    all_actions_source_data = get_fixture('policies-gen.json.js')
    return ActionExpander(PolicyGenActionsMasterList(all_actions_source_data))


def test_expand_expect_no_expansion(action_expander):

    expansion = action_expander.expand_action('s3:ListX*')
    assert expansion == {'s3:ListX*'}, 'We expect no expansion since "s3:ListX*" should not match'
    expansion = action_expander.expand_action('s3:Li*tX*')
    assert expansion == {'s3:Li*tX*'}, 'We expect no expansion since "s3:Li*tX" should not match'
    expansion = action_expander.expand_action('s3:*XX*')
    assert expansion == {'s3:*XX*'}, 'We expect no expansion since "s3:*XX*" should not match'


def test_expand_single_resource(action_expander):
    expected = {'s3:ListAllMyBuckets', 's3:ListBucketMultipartUploads', 's3:ListBucket', 's3:ListBucketVersions',
                's3:ListBucketByTags', 's3:ListMultipartUploadParts'}
    expansion = action_expander.expand_action('s3:List*')
    assert expansion == expected, 'We expect the expanded list of S3 "List" actions'
    expansion = action_expander.expand_action('s3:L*st*')
    assert expansion == expected, 'We expect the expanded list of S3 "List" actions'


def test_expand_single_resource_case_insensitive(action_expander):
    expected = {'s3:ListAllMyBuckets', 's3:ListBucketMultipartUploads', 's3:ListBucket', 's3:ListBucketVersions',
                's3:ListBucketByTags', 's3:ListMultipartUploadParts'}
    expansion = action_expander.expand_action('S3:LIST*')
    assert expansion == expected, 'We expect the all UPPERCASE [S3:LIST*] expanded list of S3 "List" actions'
    expansion = action_expander.expand_action('S3:LiSt*')
    assert expansion == expected, 'We expect the mixed case [S3:LiSt*] expanded list of S3 "List" actions'
    expansion = action_expander.expand_action('s3:list*')
    assert expansion == expected, 'We expect the all lowercase [s3:list*] expanded list of S3 "List" actions'


def test_expand_multi_splat(action_expander):
    expected = {'s3:ListAllMyBuckets'}
    expansion = action_expander.expand_action('s3:List*My*')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:List*My*"'
    expansion = action_expander.expand_action('s3:*All*Buckets')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:*All*Buckets"'
    expansion = action_expander.expand_action('s3:L*tAllMyBu*ets')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:L*tAllMyBu*ets"'
    expansion = action_expander.expand_action('s3:*AllMy*X')
    assert expansion == {'s3:*AllMy*X'}, 'We do NOT expect "s3:ListAllMyBuckets" to be matched by "s3:*AllMy*X"'
