import json

class AwsClientStub:

    def __init__(self, simulate_custom_policy_resp):
        """

        :param simulate_custom_policy_resp: JSON String
        :type simulate_custom_policy_resp: str
        """
        self.simulate_custom_policy_resp = simulate_custom_policy_resp

    def simulate_custom_policy(self, PolicyInputList, ActionNames):
        """

        :param PolicyInputList:
        :type PolicyInputList: list
        :param ActionNames:
        :type ActionNames: list
        :return:
        :rtype: dict
        """
        return json.loads(self.simulate_custom_policy_resp)