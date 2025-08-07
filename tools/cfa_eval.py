import sympy as sp
import re
from typing import List


class CFAExpressionParser:
    def __init__(self):
        self._regex_pattern = re.compile(
            r"([A-Za-z0-9]+)=([A-Za-z0-9]+)([+-]\d+)")

    def parse(self, expression: str) -> sp.Equality:
        expr_clean = expression.replace('[', '').replace(']', '')
        match = self._regex_pattern.match(expr_clean)
        if not match:
            raise ValueError(f"Invalid CFA expression: {expression}")
        left_reg, right_reg, offset_str = match.groups()
        offset_value = int(offset_str)
        left_symbol = sp.symbols(left_reg)
        right_symbol = sp.symbols(right_reg)
        return sp.Eq(left_symbol, right_symbol + offset_value)

    def parse_multiple(self, expressions: List[str]) -> List[sp.Equality]:
        return [self.parse(expr) for expr in expressions]


def main():
    parser_instance = CFAExpressionParser()
    test_expressions = ["CFA=RBP+16", "CFA=RSP+8", "R12=[CFA-24]"]
    equations = parser_instance.parse_multiple(test_expressions)
    for idx, eq in enumerate(equations, start=1):
        print(f"Parsed Equation {idx}: {eq}")

    # Solve the first equation for CFA with RBP set to 16.
    RBP_sym = sp.symbols("RBP")
    CFA_sym = sp.symbols("CFA")
    substituted_eq = equations[0].subs({RBP_sym: 16})
    solution_for_CFA = sp.solve(substituted_eq, CFA_sym)
    if solution_for_CFA:
        print(f"Solution for CFA when RBP = 16: {solution_for_CFA[0]}")
    else:
        print("No solution found for CFA.")


if __name__ == "__main__":
    main()
