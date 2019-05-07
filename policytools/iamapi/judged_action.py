import json
import logging

logger = logging.getLogger(__name__)


class JudgedAction:
    """
    You've been judged
    """

    def __init__(self, eval_result, judging_policies):
        """
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
        :param eval_result:
        :type eval_result:
        """
        self._eval_result = eval_result
        self._judging_policies = judging_policies
        self.outcome = 'deny' if eval_result['EvalDecision'] in ['explicitDeny', 'implicitDeny'] else 'allow'
        self.action_name = eval_result['EvalActionName']
        self.denial_type = None
        if eval_result['EvalDecision'] == 'explicitDeny':
            self.outcome = 'deny'
            self.denial_type = 'explicit'
        elif eval_result['EvalDecision'] == 'implicitDeny':
            self.outcome = 'deny'
            self.denial_type = 'implicit'
        elif eval_result['EvalDecision'] == 'allowed':
            self.outcome = 'allow'
            self.denial_type = None

    def __str__(self):
        return self.action_name

    def get_decider_statements(self):
        """

        :param action_name:
        :type action_name: str
        :return:
        :rtype: list
        """
        decider_policies = []
        for statement in self._eval_result['MatchedStatements']:
            # get the sub string out of the document
            decider_policy_doc = self.get_policy_by_id(statement['SourcePolicyId'])
            start_column = statement['StartPosition']['Column'] - 1
            end_column = statement['EndPosition']['Column'] -1
            decider_policies_string = json.dumps(decider_policy_doc['policy_dict'])
            decider_policies.append({
                "text": decider_policies_string[start_column:end_column],
                "policy_label": decider_policy_doc['policy_label']
            })
        return decider_policies

    def get_policy_by_id(self, source_policy_id):
        """

        :param source_policy_id: ex; PolicyInputList.1
        :type source_policy_id: str
        :return:
        :rtype:
        """

        policy_index = int(source_policy_id.split('.')[1]) - 1
        return self._judging_policies[policy_index]
