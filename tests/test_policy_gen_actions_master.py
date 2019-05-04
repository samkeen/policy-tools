import os

from policytools.lib.policy_gen_actions_master import PolicyGenActionsMaster
from tests.utils import get_fixture

master_source = get_fixture('policies-gen.json.js')

x = PolicyGenActionsMaster(master_source)
print(len(x.actions_list()))
print(sorted(x.actions_list()))