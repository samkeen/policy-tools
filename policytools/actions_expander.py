import logging
import re

logger = logging.getLogger(__name__)


class ActionsExpander():
    def __init__(self, all_resource_actions):
        self._all_actions = all_resource_actions

    def expand(self, action):
        """

        :param action:
        :type action: str
        :return:
        :rtype: list
        """
        if '*' not in action:
            return [action]
        action_pattern = action.replace('*', '.*')
        action_glob_regex = re.compile(action_pattern, re.IGNORECASE)
        expanded = [
            matched_actions for matched_actions in self._all_actions if action_glob_regex.match(matched_actions)
        ]
        if not expanded:
            logger.warning(f'No expansion was found for {action}.  Leaving this action unexpanded')
            return [action]
        return sorted(expanded)
