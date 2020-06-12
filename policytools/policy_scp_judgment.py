from typing import Set


class PolicyScpJudgment:
    denied_actions: Set[str]

    def __init__(self, denied_actions: Set[str]):
        self.denied_actions = denied_actions
