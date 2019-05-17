import json
import logging
import re

from policytools.master_list.actions_master_list_base import ActionsMasterList

logger = logging.getLogger(__name__)


class ActionExpander:
    """
    Given a policy document, apply IAM heuristics to expand the Action sets:
    - allow
    - deny (explicit)
    - deny (implicit)
    """

    def __init__(self, policy, actions_master_list):
        """

        :param policy:
        :type policy: str
        :param actions_master_list:
        :type actions_master_list: ActionsMasterList
        """
        self._actions_master_list = actions_master_list

        expanded_actions = self.expand_policy_actions(policy)
        self.denied_actions_explicit = expanded_actions['deny']['expanded']
        self.allowed_actions = expanded_actions['allow']['expanded'].difference(self.denied_actions_explicit)
        self.denied_actions_implicit = actions_master_list.all_actions_set().difference(
            self.allowed_actions).difference(self.denied_actions_explicit)

        self.allow_actions_raw = expanded_actions['allow']['raw']
        # self._allow_actions_case_preserving_lookup = expanded_actions['allow']['case_preserving_lookup']
        self.deny_actions_raw = expanded_actions['deny']['raw']
        # self._deny_actions_case_preserving_lookup = expanded_actions['deny']['case_preserving_lookup']

    def expand_policy_actions(self, policy):
        """

        :param policy: IAM policy as JSON string
        :type policy: str
        :return:
        :rtype: dict
        """
        policy_actions = {
            'allow': {
                'case_preserving_lookup': {},
                'raw': set(),
                'expanded': set()
            },
            'deny': {
                'case_preserving_lookup': {},
                'raw': set(),
                'expanded': set()
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
                for action in list(statement['Action']):
                    policy_actions[statement_effect]['case_preserving_lookup'][action.lower()] = action
                    policy_actions[statement_effect]['raw'] = policy_actions[statement_effect][
                        'raw'].union({action})
                    policy_actions[statement_effect]['expanded'] = policy_actions[statement_effect][
                        'expanded'].union(self.expand_action(action))
        return policy_actions

    def expand_action(self, action):
        """

        :param action: example 's3:*'
        :type action: str
        :return:
        :rtype: set
        """
        if '*' not in action:
            return {self._actions_master_list.lookup_action(action)}
        action_pattern = action.replace('*', '.*')
        action_glob_regex = re.compile(action_pattern, re.IGNORECASE)
        expanded = set([
            matched_actions for matched_actions in self._actions_master_list.all_actions_set() if
            action_glob_regex.match(matched_actions)
        ])
        if not expanded:
            logger.warning(f'No expansion was found for {action}.  Leaving this action unexpanded')
            return {action}
        return expanded
