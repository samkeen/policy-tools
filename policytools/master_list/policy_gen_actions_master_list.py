import json
import logging

from policytools.master_list.actions_master_list_base import ActionsMasterListBase

logger = logging.getLogger(__name__)


class PolicyGenActionsMasterList(ActionsMasterListBase):
    """
    This implementation of ActionsMasterListBase transforms the js data file from the online
    policy generator [http://awspolicygen.s3.amazonaws.com/policygen.html] into a complete Set
    of resource actions.
    js is at: https://awspolicygen.s3.amazonaws.com/js/policies.js
    """
    MASTER_SOURCE_JS_PREFIX = 'app.PolicyEditorConfig={'
    SERVICE_MAP_KEYNAME = 'serviceMap'
    source_master_json_dict = {}

    def __init__(self, source_master):
        self._resource_map = {}
        super().__init__(source_master)

    def parse_actions_source(self, source_master):
        """
        We are after the key 'serviceMap' in the returned structure

        app.PolicyEditorConfig={
          "conditionOperators": [
            "ArnEquals",
            "ArnEqualsIfExists",
              ...
          ],
          "conditionKeys": [
            "aws:CurrentTime",
            "aws:EpochTime",
              ...
          ],
          "serviceMap": {
            "Amazon Comprehend": {
              "StringPrefix": "comprehend",
              "Actions": [
                "BatchDetectDominantLanguage",
                "BatchDetectEntities",
                "BatchDetectKeyPhrases",
                  ...
        :param source_master:
        :type source_master: str
        :return:
        :rtype: set
        """
        start_of_json_index = source_master.find('{')
        if start_of_json_index == -1:
            logger.error(
                "Source master parse error: did not find opening curly brace: '{'")
            raise Exception("Parse error")
        source_master_data = {}
        try:
            self.source_master_json_dict = json.loads(source_master[start_of_json_index:])
        except json.JSONDecodeError as err:
            logger.error(f'Error parsing JSON content of master source content\nError Message:\n{err}')
        resource_actions_list = self.source_master_json_dict.get(self.SERVICE_MAP_KEYNAME)
        if resource_actions_list is None:
            raise Exception(
                f'Did not find expected key "{PolicyGenActionsMasterList.SERVICE_MAP_KEYNAME}" in master source')
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
        :rtype: set
        """
        if resource_name.lower() not in self._resource_map:
            logger.warning(f'resource {resource_name} not known. returning empty list for all_actions_for_resource()')
            return []
        return set(
            f'{resource_name}:{action}' for action in self._resource_map[resource_name.lower()]['Actions']
        )
