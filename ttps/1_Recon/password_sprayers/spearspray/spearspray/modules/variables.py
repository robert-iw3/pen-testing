from dataclasses import dataclass
from typing import List

@dataclass
class Variable:
    name: str
    description: str
    value: str

class VariablesManager:
    def __init__(self):
        self._variables: List[Variable] = []

    def register(self, name: str, description: str, value: str):
        self._variables.append(Variable(name, description, value))
    
    def get_all(self) -> List[Variable]:
        return self._variables
