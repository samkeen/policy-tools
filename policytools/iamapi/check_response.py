import logging

from policytools.iamapi.judged_action import JudgedAction

logger = logging.getLogger(__name__)

class CheckResponse:

    def __init__(self, policy_check_response, policy_list):
        """

        :param policy_check_response: JSON string
        :type policy_check_response: dict
        :param policy_list:
        :type policy_list: list
        """
        self._denied_actions_all = []
        self._allowed_actions = []
        self._raw_response = policy_check_response
        self._policy_list = policy_list
        self._parsed_response = self._parse_result(policy_check_response)

    def action_is_allowed(self, action_name):
        """

        :param action_name:
        :type action_name: str
        :return:
        :rtype:
        """
        action_result = self._parsed_response['actions_lookup'].get(action_name.lower(), 'ACTION_NOT_FOUND')
        return action_result['EvalDecision']

    def _parse_result(self, policy_check_response):
        """
        Example policy_check_response:
        {
          "EvaluationResults": [
            {
              "EvalActionName": "s3:PutObject",
              "EvalResourceName": "*",
              "EvalDecision": "allowed",
              "MatchedStatements": [
                {
                  "SourcePolicyId": "PolicyInputList.1",
                  "StartPosition": {
                    "Line": 1,
                    "Column": 41
                  },
                  "EndPosition": {
                    "Line": 1,
                    "Column": 4990
                  }
                }
              ],
              "MissingContextValues": []
            }
          ],
          "IsTruncated": false,
          "ResponseMetadata": {
            "RequestId": "156b5e01-6760-11e9-9763-7b4826eba8c8",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
              "x-amzn-requestid": "156b5e01-6760-11e9-9763-7b4826eba8c8",
              "content-type": "text/xml",
              "content-length": "975",
              "date": "Thu, 25 Apr 2019 13:43:18 GMT"
            },
            "RetryAttempts": 0
          }
        }
        :param policy_check_response:
        :type policy_check_response:
        :return:
        :rtype: dict
        """
        parsed_response = {
            'actions_lookup': {}
        }
        for eval_result in policy_check_response['EvaluationResults']:
            referenced_policies = []
            judged_action = JudgedAction(eval_result, self._policy_list)
            # build the action name lookup
            # investigate if this occurs
            assert eval_result['EvalActionName'] not in parsed_response
            parsed_response['actions_lookup'][judged_action.action_name.lower()] = eval_result
            if parsed_response['actions_lookup'][judged_action.action_name.lower()]['EvalDecision'] == 'allowed':
                self._allowed_actions.append(judged_action)
            else:
                self._denied_actions_all.append(judged_action)
        return parsed_response

    def allowed_actions(self):
        return self._allowed_actions

    def denied_actions_all(self):
        return self._denied_actions_all
