from typing import Set
from policytools.action_expander import ActionExpander


class Policy:

    denied_actions_explicit: Set[str]
    denied_actions_implicit: Set[str]
    allowed_actions: Set[str]
    allow_actions_raw: Set[str]
    deny_actions_raw: Set[str]
    unrecognized_actions: Set[str]

    def __init__(self, policy_document: str, action_expander: ActionExpander):
        """

        """

        self.original_policy_doc = policy_document
        self._action_expander = action_expander

        expanded_actions = self._action_expander.expand_policy_actions(policy_document)
        self.denied_actions_explicit = expanded_actions['deny']['explicit']
        self.denied_actions_implicit = expanded_actions['deny']['implicit']

        # @TODO need to take conditions into account
        #  simply subtracting the explicit denies from the allows is too naive, we
        # self.allowed_actions = expanded_actions['allow']['explicit'].difference(self.denied_actions_explicit)
        self.allowed_actions = expanded_actions['allow']['explicit']
        # end _todo
        self.allow_actions_raw = expanded_actions['allow']['raw']
        self.deny_actions_raw = expanded_actions['deny']['raw']
        self.unrecognized_actions = expanded_actions['unrecognized']['raw']
