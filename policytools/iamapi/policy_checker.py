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

    @classmethod
    def parse_policy(cls, policy_string):
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
        max_pagination_tries = 12  # don't dos service if we have a bug
        # make first api call to build the response object
        response = self.call_simulate_iam_policy(self._policies_list, actions_list)
        truncated = response['IsTruncated']
        marker = response.get('Marker', None)
        if truncated:
            page_call_count = 0
            # now loop calls, adding to the initial response.EvaluationResults
            while truncated and page_call_count <= max_pagination_tries:
                page_call_count += 1
                page_response = self.call_simulate_iam_policy(self._policies_list, actions_list, marker)
                response['EvaluationResults'] = response['EvaluationResults'] + page_response['EvaluationResults']
                truncated = page_response['IsTruncated']
                marker = page_response.get('Marker', None)
                if truncated and page_call_count == max_pagination_tries:
                    raise RuntimeError(f'Made max [{page_call_count}] allowed calls to simulate_custom_policy'
                                       f'exiting so we don\'t dos the service')
        return CheckResponse(response, self._policies_list)

    def get_context_keys_for_policy(self):
        policies_list = [json.dumps(policy['policy_dict']) for policy in self._policies_list]
        response = self._aws_client.get_context_keys_for_custom_policy(
            PolicyInputList=policies_list
        )
        return response

    def call_simulate_iam_policy(self, policy_input_list, action_names, marker: str = ''):
        """

        :param policy_input_list:
        :type policy_input_list: list
        :param action_names:
        :type action_names: list
        :return:
        :rtype: dict
        # PolicyInputList=[],
            # ActionNames=[],
            # Marker=string
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
        """
        call_options = {
            'PolicyInputList': [json.dumps(policy['policy_dict']) for policy in policy_input_list],
            'ActionNames': action_names
        }
        if marker:
            call_options['Marker'] = marker
        response = self._aws_client.simulate_custom_policy(**call_options)
        return response
