import json
import logging
import re

from policytools.master_list.actions_master_list_base import ActionsMasterListBase

logger = logging.getLogger(__name__)


class ActionExpander:
    """
    Given a policy document, apply IAM heuristics to expand the Action sets:
    - allow
    - deny (explicit)
    - deny (implicit)
    """

    def __init__(self, actions_master_list):
        """

        :param actions_master_list:
        :type actions_master_list: ActionsMasterListBase
        """
        self._actions_master_list = actions_master_list

    def expand_policy_actions(self, policy: str):
        """

        :param policy: IAM policy as JSON string
        """
        policy_actions = {
            'allow': {
                'raw': set(),
                'explicit': set()
                # IAM logic does not support for implicit Allow
            },
            'deny': {
                'raw': set(),
                'explicit': set(),
                'implicit': set()
            },
            'unrecognized': {
                'raw': set()
            }
        }
        try:
            policy_data = json.loads(policy)
        except json.JSONDecodeError as err:
            logger.error(f'Error parsing User Policy string: {policy}')
            raise err

        for statement in policy_data['Statement']:
            statement_effect = statement['Effect'].lower()
            if statement_effect not in ['allow', 'deny']:
                logger.error(f'Unknown statement Effect; "{statement_effect}". Ignoring statement: {statement}')
            else:
                # ensure we have a list
                actions = [statement['Action']] if isinstance(statement['Action'], str) else statement['Action']
                for action in actions:
                    # add this raw statement to our already 'seen' list
                    policy_actions[statement_effect]['raw'] = policy_actions[statement_effect]['raw'].union({action})
                    expanded_action_set = self.expand_action(action)
                    if not expanded_action_set:
                        policy_actions['unrecognized']['raw'].add(action)
                    else:
                        matched_actions = policy_actions[statement_effect]['explicit'].union(expanded_action_set)
                        policy_actions[statement_effect]['explicit'] = matched_actions
        policy_actions['deny']['implicit'] = self._actions_master_list.all_actions_set().difference(
            policy_actions['allow']['explicit']).difference(policy_actions['deny']['explicit'])

        return policy_actions

    def expand_action(self, action):
        """

        :param action: example 's3:*'
        :type action: str
        :return:
        :rtype: set
        """
        if '*' not in action:

            action_lookup = self._actions_master_list.lookup_action(action)
            if not action_lookup:
                return set()
            else:
                return {action_lookup}
        action_pattern = action.replace('*', '.*')
        action_glob_regex = re.compile(action_pattern, re.IGNORECASE)
        expanded = set([
            matched_actions for matched_actions in self._actions_master_list.all_actions_set() if
            action_glob_regex.match(matched_actions)
        ])
        if not expanded:
            logger.warning(f'No expansion was found for {action}.  Leaving this action unexpanded')
            return set()
        return expanded
