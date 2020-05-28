import json
import logging
import re
from typing import List, Type, Dict, Any, Set

from policytools.master_list.actions_master_list_base import ActionsMasterListBase

logger = logging.getLogger(__name__)


class ActionExpander:
    """
    Given a policy document, apply IAM heuristics to expand the Action sets:
    - allow
    - deny (explicit)
    - deny (implicit)
    """
    _actions_master_list: Type[ActionsMasterListBase]
    _filter_conditional_denials: bool
    _processed_conditional_deny_statements: List = []
    # these are tracked separately.  _filter_conditional_denials determines if they are included in
    # the denials returned from expand_policy_actions()
    _conditional_deny_actions: Set = set()

    def __init__(self, actions_master_list: Type[ActionsMasterListBase], filter_conditional_denials=False):
        """

        """
        self._actions_master_list = actions_master_list
        self._filter_conditional_denials = filter_conditional_denials

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
                continue
            is_conditional = self._record_conditional_denial(statement)
            if is_conditional and self._filter_conditional_denials:
                logger.info(f'Filtering conditional denial statement: "{statement}"')
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
                    if is_conditional:
                        self._conditional_deny_actions = matched_actions
                    if not is_conditional or not self._filter_conditional_denials:
                        logger.info(f'Filtering conditional denial actions: "{matched_actions}"')
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

    def _is_conditional_denial(self, statement: Dict[str, Any]):
        statement = {k.lower(): v for k, v in statement.items()}
        is_conditional_denial = False
        if statement['effect'].lower() == 'deny':
            is_conditional_denial = statement['resource'] != '*' or statement.get('condition', False)
        return is_conditional_denial

    def _record_conditional_denial(self, statement: Dict[str, Any]):
        recorded = False
        if self._is_conditional_denial(statement):
            self._processed_conditional_deny_statements.append(statement)
            recorded = True
        return recorded

    @property
    def conditional_denied_actions(self):
        return self._conditional_deny_actions
