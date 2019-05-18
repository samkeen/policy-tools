from policytools.policy import Policy
from policytools.policy_scp_judgment import PolicyScpJudgment


class ServiceControlPolicy(Policy):

    def __init__(self, policy_document, action_expander):
        super().__init__(policy_document, action_expander)

    def effect_on(self, user_policy):
        """

        :param user_policy:
        :type user_policy: Policy
        :return:
        :rtype:
        """
        return PolicyScpJudgment(
            denied_actions=user_policy.allowed_actions.intersection(
                self.denied_actions_explicit.union(self.denied_actions_implicit))
        )
