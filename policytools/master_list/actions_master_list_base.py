import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ActionsMasterListBase(ABC):
    """
    Base class meant to hold the entire Set of IAM resource actions.
    It is up to a concrete class to implement a source document parser (parse_actions_source)
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

