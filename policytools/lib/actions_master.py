from abc import ABC, abstractmethod


class ActionsMaster(ABC):
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
        self._actions_list = self.parse_actions_source(source_master)
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

    def actions_list(self):
        return self._actions_list


