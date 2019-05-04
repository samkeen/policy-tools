import json
import logging

from policytools.lib.actions_master import ActionsMaster

logger = logging.getLogger(__name__)


class PolicyGenActionsMaster(ActionsMaster):
    """
    This implementation of ActionsMaster transforms the js data file from the online
    policy generator [http://awspolicygen.s3.amazonaws.com/policygen.html] into a complete Set
    of resource actions.
    """

    def __init__(self, source_master):
        self._resource_map = {}
        super().__init__(source_master)

    MASTER_SOURCE_JS_PREFIX = 'app.PolicyEditorConfig={'
    SERVICE_MAP_KEYNAME = 'serviceMap'

    def parse_actions_source(self, source_master):
        """

        :param source_master:
        :type source_master: str
        :return:
        :rtype: set
        """
        found_prefix = source_master[0:len(PolicyGenActionsMaster.MASTER_SOURCE_JS_PREFIX)]
        if found_prefix != PolicyGenActionsMaster.MASTER_SOURCE_JS_PREFIX:
            logger.error(
                f"Source master parse error: Expected {PolicyGenActionsMaster.MASTER_SOURCE_JS_PREFIX}, found {found_prefix}")
            raise Exception("Parse error")
        source_master_data = {}
        try:
            source_master_data = json.loads(source_master[len(PolicyGenActionsMaster.MASTER_SOURCE_JS_PREFIX) - 1:])
        except json.JSONDecodeError as err:
            logger.error(f'Error parsing JSON content of master source content\nError Message:\n{err}')
        resource_actions_list = source_master_data.get(self.SERVICE_MAP_KEYNAME)
        if resource_actions_list is None:
            raise Exception(
                f'Did not find expected key "{PolicyGenActionsMaster.SERVICE_MAP_KEYNAME}" in master source')
        actions_set = set()
        for resource_name, resource_data in resource_actions_list.items():
            self._resource_map[resource_data['StringPrefix']] = resource_data
            self._resource_map[resource_data['StringPrefix']]['ResourceLabel'] = resource_name
            for action in resource_data['Actions']:
                actions_set.add(f'{resource_data["StringPrefix"]}:{action}')
        logger.info(f'Actions list contains {len(actions_set)} items')
        return actions_set

    def all_actions_for_resource(self, resource_name):
        """
        Returns all known actions (in form '{resource_name}:{action}') for the given resource
        :param resource_name:
        :type resource_name: str
        :return:
        :rtype: list
        """
        if resource_name.lower() not in self._resource_map:
            logger.warning(f'resource {resource_name} not known. returning empty list for all_actions_for_resource()')
            return []
        return sorted([
            f'{resource_name}:{action}' for action in self._resource_map[resource_name.lower()]['Actions']
        ])
