import logging
import re

logger = logging.getLogger(__name__)


class ActionRequestAnalyzer:
    def __init__(self, all_resource_actions):
        self._all_actions = all_resource_actions

    def expand(self, action):
        """

        :param action:
        :type action: str
        :return:
        :rtype: set
        """
        if '*' not in action:
            return [action]
        action_pattern = action.replace('*', '.*')
        action_glob_regex = re.compile(action_pattern, re.IGNORECASE)
        expanded = set([
            matched_actions for matched_actions in self._all_actions if action_glob_regex.match(matched_actions)
        ])
        if not expanded:
            logger.warning(f'No expansion was found for {action}.  Leaving this action unexpanded')
            return [action]
        return expanded

    def denied_actions(self, requested_actions, allowable_actions):
        """
        This is a Case preserving, Case insensitive comparison
        :param requested_actions:
        :type requested_actions:  set
        :param allowable_actions:
        :type allowable_actions: set
        :return:
        :rtype: set
        """
        case_lookup_map = {action.lower(): action for action in allowable_actions}
        requested_actions_lower = set(action.lower() for action in requested_actions)
        allowed_actions_lower = set(action.lower() for action in allowable_actions)
        denials = allowed_actions_lower.difference(requested_actions_lower)
        return set(case_lookup_map[denial] for denial in denials if denial in case_lookup_map)
