from policytools.actions_expander import ActionsExpander
from policytools.lib.policy_gen_actions_master import PolicyGenActionsMaster
from tests.utils import get_fixture


def test_expect_no_expansion():
    all_actions_source_data = get_fixture('policies-gen.json.js')
    all_resource_actions = PolicyGenActionsMaster(all_actions_source_data)
    expander = ActionsExpander(all_resource_actions.actions_list())
    expansion = expander.expand('s3:ListX*')
    assert expansion == ['s3:ListX*'], 'We expect no expansion since "ListX" should not match'
    expansion = expander.expand('s3:Li*tX*')
    assert expansion == ['s3:Li*tX*'], 'We expect no expansion since "ListX" should not match'
    expansion = expander.expand('s3:*XX*')
    assert expansion == ['s3:*XX*'], 'We expect no expansion since "ListX" should not match'


def test_single_resource():
    expected = sorted(['s3:ListAllMyBuckets', 's3:ListBucketMultipartUploads', 's3:ListBucket', 's3:ListBucketVersions',
                       's3:ListBucketByTags', 's3:ListMultipartUploadParts'])
    all_actions_source_data = get_fixture('policies-gen.json.js')
    all_resource_actions = PolicyGenActionsMaster(all_actions_source_data)
    expander = ActionsExpander(all_resource_actions.actions_list())
    expansion = expander.expand('s3:List*')
    assert expansion == expected, 'We expect the expanded list of S3 "List" actions'
    expansion = expander.expand('s3:L*st*')
    assert expansion == expected, 'We expect the expanded list of S3 "List" actions'


def test_single_resource_case_insensitive():
    expected = sorted(
        ['s3:ListAllMyBuckets', 's3:ListBucketMultipartUploads', 's3:ListBucket', 's3:ListBucketVersions',
         's3:ListBucketByTags', 's3:ListMultipartUploadParts'])
    all_actions_source_data = get_fixture('policies-gen.json.js')
    all_resource_actions = PolicyGenActionsMaster(all_actions_source_data)
    expander = ActionsExpander(all_resource_actions.actions_list())
    expansion = expander.expand('S3:LIST*')
    assert expansion == expected, 'We expect the all UPPERCASE [S3:LIST*] expanded list of S3 "List" actions'
    expansion = expander.expand('S3:LiSt*')
    assert expansion == expected, 'We expect the mixed case [S3:LiSt*] expanded list of S3 "List" actions'
    expansion = expander.expand('s3:list*')
    assert expansion == expected, 'We expect the all lowercase [s3:list*] expanded list of S3 "List" actions'


def test_multi_splat():
    expected = sorted(['s3:ListAllMyBuckets'])
    all_actions_source_data = get_fixture('policies-gen.json.js')
    all_resource_actions = PolicyGenActionsMaster(all_actions_source_data)
    expander = ActionsExpander(all_resource_actions.actions_list())
    expansion = expander.expand('s3:List*My*')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:List*My*"'
    expansion = expander.expand('s3:*All*Buckets')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:*All*Buckets"'
    expansion = expander.expand('s3:L*tAllMyBu*ets')
    assert expansion == expected, 'We expect "s3:ListAllMyBuckets" to be matched by "s3:L*tAllMyBu*ets"'
    expansion = expander.expand('s3:*AllMy*X')
    assert expansion == ['s3:*AllMy*X'], 'We do NOT expect "s3:ListAllMyBuckets" to be matched by "s3:*AllMy*X"'


def test_match_all_actions_for_just_splat():
    all_actions_source_data = get_fixture('policies-gen.json.js')
    all_resource_actions = PolicyGenActionsMaster(all_actions_source_data)
    expected = all_resource_actions.all_actions_for_resource('ec2')
    expander = ActionsExpander(all_resource_actions.actions_list())

    expansion = expander.expand('ec2:*')
    assert expansion == expected, 'We expect all the EC2 actions to be matched by "ec2:*"'
