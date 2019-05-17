import re
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ActionsMasterList(ABC):
    """
    Base class defining the strategy to transform a source document listing
    all IAM Resource actions into a Set of those actions.
    This complete set of actions is used for action expansions (see ActionsExpander).
    """

    def __init__(self, source_master):
        """

        :param source_master:
        :type source_master: str
        """
        self._actions_set = self.parse_actions_source(source_master)
        self._actions_set_case_insensitive_lookup = {resource_action.lower(): resource_action for resource_action in
                                                     self._actions_set}
        super().__init__()

    @abstractmethod
    def parse_actions_source(self, source_master):
        """

        :param source_master:
        :type source_master: str
        :return:
        :rtype: set
        """
        pass

    @abstractmethod
    def all_actions_for_resource(self, resource_name):
        """
        This must return a sorted list of all actions for the given resource
        :param resource_name:
        :type resource_name: str
        :return:
        :rtype: list
        """

    def all_actions_set(self, lower=False):
        return set(item.lower() for item in self._actions_set) if lower else self._actions_set

    def lookup_action(self, action):
        """
        Case insensitive lookup for all known actions. Returned in PascalCase
        :param action:
        :type action: str
        :return:
        :rtype: str
        """
        return self._actions_set_case_insensitive_lookup[action.lower()]

    def expand(self, action):
        """

        :param action:
        :type action: set
        :return:
        :rtype: set
        """
        if '*' not in action:
            return {self._actions_set_case_insensitive_lookup[action.lower()]}
        action_pattern = action.replace('*', '.*')
        action_glob_regex = re.compile(action_pattern, re.IGNORECASE)
        expanded = set([
            matched_actions for matched_actions in self._actions_set if action_glob_regex.match(matched_actions)
        ])
        if not expanded:
            logger.warning(f'No expansion was found for {action}.  Leaving this action unexpanded')
            return {action}
        return expanded
