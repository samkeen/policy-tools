from policytools.action_expander import ActionExpander


class Policy:

    def __init__(self, policy_document, action_expander):
        """

        :param policy_document:
        :type policy_document:
        :param action_expander:
        :type action_expander: ActionExpander
        """

        self.original_policy_doc = policy_document
        self._action_expander = action_expander

        expanded_actions = self._action_expander.expand_policy_actions(policy_document)
        self.denied_actions_explicit = expanded_actions['deny']['explicit']
        self.denied_actions_implicit = expanded_actions['deny']['implicit']
        self.allowed_actions = expanded_actions['allow']['explicit'].difference(self.denied_actions_explicit)
        self.allow_actions_raw = expanded_actions['allow']['raw']
        self.deny_actions_raw = expanded_actions['deny']['raw']
