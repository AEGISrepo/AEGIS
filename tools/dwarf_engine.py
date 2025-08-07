import os
import re
import logging
import pickle
from functools import cache
from collections import defaultdict
import sympy as sp

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')


class DWARFExpressionEngine:
    def __init__(self, cfa: sp.Eq = None):
        self.cfa = cfa
        self.stack = []
        self.dispatcher = {
            'DW_OP_lit': self._handle_lit,
            'DW_OP_stack_value': self._handle_stack_value,
            'DW_OP_reg': self._handle_reg,
            'DW_OP_breg': self._handle_breg,
            'DW_OP_const': self._handle_const,
            'DW_OP_and': self._handle_and,
            'DW_OP_or': self._handle_or,
            'DW_OP_xor': self._handle_xor,
            'DW_OP_shl': self._handle_shl,
            'DW_OP_shr': self._handle_shr,
            'DW_OP_shra': self._handle_shr,
            'DW_OP_entry_value': self._handle_entry_value,
            'DW_OP_minus': self._handle_minus,
            'DW_OP_plus': self._handle_plus,
            'DW_OP_plus_uconst': self._handle_plus_uconst,
            'DW_OP_fbreg': self._handle_fbreg,
            'DW_OP_deref_size': self._handle_deref,
            'DW_OP_deref': self._handle_deref,
            'DW_OP_addr': self._handle_addr,
            'DW_OP_neg': self._handle_neg
        }

    def _to_name(self, sym):
        if isinstance(sym, sp.Integer):
            return hex(int(sym))
        return str(sym)

    def evaluate(self, expr: str):
        self.stack = []
        tokens = [token.strip() for token in expr.strip().split(',')]
        termination_flag = False
        for token in tokens:
            token = token.strip()
            if termination_flag and token:
                raise AssertionError(
                    "Expression terminated prematurely; extra token encountered.")
            handled = False
            for op_key in self.dispatcher.keys():
                if token.startswith(op_key):
                    self.dispatcher[op_key](token)
                    handled = True
                    break
            if not handled:
                raise NotImplementedError(
                    f"Operation {token} is not implemented.")
            if token == 'DW_OP_stack_value':
                termination_flag = True
        if not self.stack:
            raise AssertionError("Evaluation resulted in an empty stack.")
        if self.stack[-1] == "stack_value":
            if len(self.stack) != 2:
                raise AssertionError(
                    "Stack length error with DW_OP_stack_value.")
            return self.stack[0]
        if isinstance(self.stack[0], str) and self.stack[0].startswith('R') and len(self.stack[0]) < 4:
            if len(self.stack) != 1:
                raise AssertionError(
                    "Unexpected stack length for register value.")
            return self.stack[0]
        if len(self.stack) != 1:
            raise AssertionError(
                "Final stack does not contain exactly one element.")
        result = self.stack.pop()
        if isinstance(result, sp.Integer):
            return sp.Symbol(f'deref({hex(int(result))})')
        return sp.Symbol(f'deref({result})')

    def _handle_lit(self, token: str):
        literal = int(token[len('DW_OP_lit'):])
        self.stack.append(sp.Integer(literal))

    def _handle_stack_value(self, token: str):
        if len(self.stack) == 1:
            self.stack.append("stack_value")
        else:
            raise ValueError(
                "Stack is not in a valid state for DW_OP_stack_value.")

    def _handle_reg(self, token: str):
        match = re.match(r'DW_OP_reg\d+\s+(\w+)', token)
        if match:
            reg_name = match.group(1)
            self.stack.append(sp.Symbol(reg_name))
        else:
            raise ValueError(f"Invalid DW_OP_reg operation: {token}")

    def _handle_breg(self, token: str):
        parts = token[len('DW_OP_breg'):].split('+')
        if len(parts) < 2:
            raise ValueError("DW_OP_breg token format invalid.")
        reg_part = parts[0].strip().split()
        if len(reg_part) < 2:
            raise ValueError(
                "Missing register identifier in DW_OP_breg token.")
        reg_name = reg_part[1]
        offset = int(parts[1].strip()) if len(parts) > 1 else 0
        if offset > 0:
            self.stack.append(sp.Symbol(f'{reg_name} + {offset}'))
        elif offset < 0:
            self.stack.append(sp.Symbol(f'{reg_name} - {-offset}'))
        else:
            self.stack.append(sp.Symbol(f'{reg_name}'))

    def _handle_const(self, token: str):
        const_val = token.split(' ', 1)[-1].strip()
        if 'x' in const_val:
            value = int(const_val, 16)
        else:
            value = int(const_val)
        self.stack.append(sp.Integer(value))

    def _handle_and(self, token: str):
        if len(self.stack) < 2:
            raise ValueError("Insufficient values for DW_OP_and.")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(
            sp.Symbol(f'({self._to_name(a)} & {self._to_name(b)})'))

    def _handle_or(self, token: str):
        if len(self.stack) < 2:
            raise ValueError("Insufficient values for DW_OP_or.")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(
            sp.Symbol(f'({self._to_name(a)} | {self._to_name(b)})'))

    def _handle_xor(self, token: str):
        if len(self.stack) < 2:
            raise ValueError("Insufficient values for DW_OP_xor.")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(
            sp.Symbol(f'({self._to_name(a)} ^ {self._to_name(b)})'))

    def _handle_shl(self, token: str):
        if len(self.stack) < 2:
            raise ValueError("Insufficient values for DW_OP_shl.")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(
            sp.Symbol(f'(({self._to_name(a)}) << {self._to_name(b)})'))

    def _handle_shr(self, token: str):
        if len(self.stack) < 2:
            raise ValueError("Insufficient values for DW_OP_shr/shra.")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(
            sp.Symbol(f'(({self._to_name(a)}) >> {self._to_name(b)})'))

    def _handle_entry_value(self, token: str):
        pattern = r'DW_OP_entry_value\((?:DW_OP_\w+\s+)?(\w+)\)'
        match = re.search(pattern, token)
        if match:
            res = f'DW_OP_entry_value({match.group(1)})'
            self.stack.append(sp.Symbol(res))
        else:
            raise ValueError(f"Invalid DW_OP_entry_value operation: {token}")

    def _handle_minus(self, token: str):
        if len(self.stack) < 2:
            raise ValueError("Insufficient values for DW_OP_minus.")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(
            sp.Symbol(f'({self._to_name(a)} - {self._to_name(b)})'))

    def _handle_plus(self, token: str):
        if len(self.stack) < 2:
            raise ValueError("Insufficient values for DW_OP_plus.")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(
            sp.Symbol(f'({self._to_name(a)} + {self._to_name(b)})'))

    def _handle_plus_uconst(self, token: str):
        offset_str = token[len('DW_OP_plus_uconst'):].strip()
        offset = int(offset_str, 16)
        if not self.stack:
            raise ValueError("Stack underflow for DW_OP_plus_uconst.")
        a = self.stack.pop()
        self.stack.append(a + offset)

    def _handle_fbreg(self, token: str):
        offset_str = token[len('DW_OP_fbreg'):].strip()
        offset = int(offset_str)
        frame_base = self.cfa.rhs if self.cfa is not None else sp.Symbol(
            'frame_base')
        if offset != 0:
            result = frame_base + offset
            self.stack.append(sp.Symbol(f'{result}'))
        else:
            self.stack.append(frame_base)

    def _handle_deref(self, token: str):
        if not self.stack:
            raise ValueError("Stack underflow for dereference operation.")
        a = self.stack.pop()
        self.stack.append(sp.Symbol(f'deref({a})'))

    def _handle_addr(self, token: str):
        addr_str = token[len('DW_OP_addr'):].strip()
        addr = int(addr_str, 16)
        self.stack.append(sp.Integer(addr))

    def _handle_neg(self, token: str):
        if not self.stack:
            raise ValueError("Stack underflow for DW_OP_neg.")
        a = self.stack.pop()
        self.stack.append(-a)
        a_val = self.stack.pop()
        self.stack.append(sp.Symbol(f'({a_val})'))


def convert_decimals_to_hex(sym_str: str) -> str:
    pattern = r'\b\d+\b'

    def repl(match):
        num = int(match.group(0))
        if num > 0x1000:
            return hex(num)
        return match.group(0)
    return re.sub(pattern, repl, sym_str)


def dwarf_calculate_engine(ops: list[str], cfa: sp.Eq = None) -> str:
    if len(ops) != 1:
        raise ValueError("Only a single DWARF expression is allowed.")
    engine = DWARFExpressionEngine(cfa)
    result = engine.evaluate(ops[0])
    return convert_decimals_to_hex(str(result))


if __name__ == '__main__':
    filename = 'dwarfexpressions.txt'
    if not os.path.exists(filename):
        logging.error("File %s does not exist.", filename)
        exit(1)
    with open(filename, 'r') as infile:
        for line in infile:
            expr = line.strip()
            if not expr:
                continue
            logging.debug("Evaluating: %s", expr)
            try:
                output = dwarf_calculate_engine([expr])
                print("Input:", expr)
                print("Output:", output)
                print()
            except Exception as e:
                logging.error("Error processing '%s': %s", expr, e)
