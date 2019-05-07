import json

import logging

from policytools.iamapi.check_response import CheckResponse

logger = logging.getLogger(__name__)


class PolicyChecker:

    def __init__(self, aws_client):
        self._aws_client = aws_client
        self._policies_list = []

    def append_policy(self, policy_label, policy_string):
        """
        Add a policy document to which the actions will be accesses.
        :param policy_label: Name used to reference Policy going forward.  Filename is a good choice
        :type policy_label: str
        :param policy_string: Needs to be valid JSON
        :type policy_string: str
        :return:
        :rtype: None
        """
        self._policies_list.append(
            {
                'policy_label': policy_label,
                'policy_dict': self.parse_policy(policy_string)
            }
        )

    @staticmethod
    def parse_policy(policy_string):
        try:
            policy_data = json.loads(policy_string)
        except json.JSONDecodeError as err:
            logger.error(f'Error JSON parser error on policy: {policy_string}')
            raise err
        return policy_data

    def check_actions(self, actions_list):
        """

        :param actions_list:
        :type actions_list: list
        :return:
        :rtype:
        """
        response = self.call_simulate_iam_policy(self._policies_list, actions_list)
        return CheckResponse(response, self._policies_list)

    def call_simulate_iam_policy(self, policy_input_list, action_names):
        """

        :param policy_input_list:
        :type policy_input_list: list
        :param action_names:
        :type action_names: list
        :return:
        :rtype: dict
        """
        response = self._aws_client.simulate_custom_policy(
            # grab the policies as strings
            PolicyInputList=[json.dumps(policy['policy_dict']) for policy in policy_input_list],
            ActionNames=action_names
            # ResourceArns=[
            #     'string',
            # ],
            # ResourcePolicy='string',
            # ResourceOwner='string',
            # CallerArn='string',
            # ContextEntries=[
            #     {
            #         'ContextKeyName': 'string',
            #         'ContextKeyValues': [
            #             'string',
            #         ],
            #         'ContextKeyType': 'string' | 'stringList' | 'numeric' | 'numericList' | 'boolean' | 'booleanList' | 'ip' | 'ipList' | 'binary' | 'binaryList' | 'date' | 'dateList'
            #     },
            # ],
            # ResourceHandlingOption='string',
            # MaxItems=123,
            # Marker='string'
        )
        return response