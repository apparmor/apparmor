#
# ----------------------------------------------------------------------
#    Copyright (C) 2025 Canonical, Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------

import ast
import re

from apparmor.common import AppArmorException, AppArmorBug
from apparmor.regex import strip_quotes, RE_PROFILE_CONDITIONAL_START, RE_PROFILE_CONDITIONAL_ELSE, RE_ALL_VARIABLES, RE_BOOLEAN_OP, RE_ID_OR_VAR, RE_CONDITION, RE_COMPARE_OP_QUOTED
from apparmor.rule import BaseRule, BaseRuleset, parse_comment, quote_if_needed
from apparmor.translations import init_translation

_ = init_translation()


class ConditionalBlock(BaseRule):
    """Class to handle and store a conditional block containing if,
    and optionally, else ifs and else"""

    _match_re = None
    result = False

    def __init__(self, raw_rule, prof_storage, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                         comment=comment, log_event=log_event, priority=priority)

        # conditional blocks don't support priority, allow keyword, audit or deny - yet
        self.ensure_modifiers_not_supported()

        self.cond_list = []
        conditional = ConditionalStart.create_instance(raw_rule)
        self.result = conditional.evaluate(prof_storage)
        self.cond_list.append(conditional)

    def store_profile_data(self, profile_data):
        self.cond_list[-1].profile_data = profile_data

    def add_conditional(self, raw_rule, prof_storage):
        conditional = ConditionalElse.create_instance(raw_rule)
        result = conditional.evaluate(prof_storage)
        self.cond_list.append(conditional)
        if self.result:
            self.result = False
        else:
            self.result = result

    def get_clean(self, depth=0):
        clean = ''
        for cond in self.cond_list:
            if clean:
                clean += ' '
            clean += cond.get_clean(depth)
        return clean

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        raise NotImplementedError("'%s' is not supposed to be called directly" % (str(cls)))

    def _is_covered_localvars(self, other_rule):
        """check if other_rule is covered by this rule object"""
        if len(self.cond_list) != len(other_rule.cond_list):
            return False
        else:
            for idx in range(len(self.cond_list)):
                if not self.cond_list[idx].is_covered(other_rule.cond_list[idx]):
                    return False
        return True

    def _is_equal_localvars(self, other_rule, strict):
        """compare if rule-specific conditionals are equal"""
        if len(self.cond_list) != len(other_rule.cond_list):
            return False
        else:
            for idx in range(len(self.cond_list)):
                if not self.cond_list[idx].is_equal(other_rule.cond_list[idx]):
                    return False
        return True

    def _logprof_header_localvars(self):
        conditions = []
        for cond in self.cond_list:
            conditions.append(cond.logprof_header())
        return _('ConditionalBlock'), (conditions)


class ConditionalRule(BaseRule):
    """Class to handle and store a single conditional rule"""

    IF = 1
    ELSEIF = 2
    ELSE = 3
    rule_name = 'conditional'
    _match_re = re.compile(RE_CONDITION)

    def __init__(self, condition, ast_tree,
                 audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, priority=None):

        super().__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                         comment=comment, log_event=log_event, priority=priority)

        # conditionals don't support priority, allow keyword, audit or deny
        self.ensure_modifiers_not_supported()

        if condition not in [self.IF, self.ELSEIF, self.ELSE]:
            raise AppArmorBug('Passed invalid condition to %s: %s' % (self.__class__.__name__, condition))
        if ast_tree is not None and not isinstance(ast_tree, AppArmorAst):
            raise AppArmorBug('Passed invalid AST tree type to %s: %s' % (self.__class__.__name__, type(ast_tree)))

        self.condition = condition
        self.ast_tree = ast_tree

    @classmethod
    def _create_instance(cls, raw_rule, matches):
        """parse raw_rule and return instance of this class"""

        if cls == ConditionalStart:
            conditional = ConditionalRule.IF
        else:
            if matches.group('if'):
                conditional = ConditionalRule.ELSEIF
            else:
                conditional = ConditionalRule.ELSE

        comment = parse_comment(matches)

        expr = cls._match_re.search(raw_rule)
        ast_tree = None
        if conditional != ConditionalRule.ELSE:
            ast_tree = AppArmorAst(expr.group('expr'))

        return cls(conditional, ast_tree, comment)

    def evaluate(self, prof_storage):
        # else should always evaluate to true, since that's the
        # default if all previous "ifs" evaluated to false
        if self.condition == ConditionalRule.ELSE:
            return True

        return self.ast_tree.evaluate(prof_storage)

    def get_clean(self, depth=0):
        """return rule (in clean/default formatting)"""

        space = '  ' * depth
        leading_space = ''
        if self.condition == ConditionalRule.IF:
            conditional = 'if '
            leading_space = space
        elif self.condition == ConditionalRule.ELSEIF:
            conditional = 'else if '
        elif self.condition == ConditionalRule.ELSE:
            conditional = 'else '
        else:
            raise AppArmorBug('Invalid condition type in %s' % (self.__class__.__name__))

        expr = ''
        if self.ast_tree:
            expr = self.ast_tree.get_clean()

        data = []
        data.append('%s%s%s{' % (leading_space, conditional, expr))

        for profname in self.profile_data:
            if self.profile_data[profname]['in_cond']:
                from apparmor.aa import write_piece
                data.extend(write_piece(self.profile_data, depth + 1, profname, profname))
            else:
                data += self.profile_data[profname].get_rules_clean(depth + 1)

        data.append('%s}' % space)
        return '\n'.join(data)

    def _is_covered_localvars(self, other_rule):
        """check if other_rule is covered by this rule object"""
        # conditional is only covered if equal
        if self.is_equal(other_rule):
            return True
        return False

    def _is_equal_localvars(self, rule_obj, strict):
        """compare if rule-specific conditionals are equal"""
        if self.condition != rule_obj.condition:
            return False
        if self.profile_data != rule_obj.profile_data:
            return False
        return self.ast_tree.is_equal(rule_obj.ast_tree)

    def _logprof_header_localvars(self):
        return _('Conditional'), self.get_clean()


class ConditionalStart(ConditionalRule):
    """Class to handle and store a single conditional rule"""

    _match_re = RE_PROFILE_CONDITIONAL_START


class ConditionalElse(ConditionalRule):
    """Class to handle and store a single conditional rule"""

    _match_re = RE_PROFILE_CONDITIONAL_ELSE


class ConditionalBlockset(BaseRuleset):
    """Class to handle and store a collection of conditional rule blocks"""


class AppArmorAst():
    astcomp_to_string = {
        ast.Eq: '==',
        ast.NotEq: '!=',
        ast.Lt: '<',
        ast.LtE: '<=',
        ast.Gt: '>',
        ast.GtE: '>=',
        ast.In: 'in',
    }

    def __init__(self, expr):
        self.tree = ast.parse(self.transform_cond(expr))

    def get_clean(self):
        noop, expr = self.get_clean_tree(self.tree.body[0])
        expr += ' '
        return expr

    def get_clean_tree(self, node):
        if isinstance(node, ast.Expr):
            node = node.value
        if isinstance(node, ast.BoolOp):
            op = ''
            clean = ''
            if isinstance(node.op, ast.And):
                op = 'and'
            else:
                op = 'or'
            for value in node.values:
                if clean:
                    clean += ' ' + op + ' '
                ret_op, ret_clean = self.get_clean_tree(value)
                if ret_op == 'or' and op == 'and':
                    ret_clean = '(' + ret_clean + ')'
                clean += ret_clean
            return op, clean
        elif isinstance(node, ast.UnaryOp):
            if not isinstance(node.op, ast.Not):
                raise AppArmorBug('Invalid unary operation in %s' % (self.__class__.__name__))
            op, child = self.get_clean_tree(node.operand)
            if op == 'not':  # remove canceling nots
                return 'val', '%s' % (child[len('not '):])
            return 'not', 'not %s' % (child)
        elif isinstance(node, ast.Constant):
            val = quote_if_needed(strip_quotes(node.value))  # strip first because it can be quoted but not need it
            term = Term.create_instance(val)
            return 'val', str(term)
        elif isinstance(node, ast.Name):
            return 'func', node.id
        elif isinstance(node, ast.Call):
            noop, name = self.get_clean_tree(node.func)
            if name != 'defined':
                raise AppArmorBug('Invalid function name in %s' % (self.__class__.__name__))
            noop, var = self.get_clean_tree(node.args[0])
            return 'defined', '%s %s' % (name, var)
        elif isinstance(node, ast.Compare):
            noop, left = self.get_clean_tree(node.left)
            noop, right = self.get_clean_tree(node.comparators[0])
            op = self.astcomp_to_string[type(node.ops[0])]
            return 'cmp', '%s %s %s' % (left, op, right)
        else:
            raise AppArmorBug('Unsupported node type in %s' % (self.__class__.__name__))

    def evaluate(self, prof_storage):
        noop, result = self.evaluate_tree(self.tree.body[0], prof_storage, True)
        return result

    def evaluate_tree(self, node, prof_storage, resolve=False):
        result = None
        if isinstance(node, ast.Expr):
            node = node.value
        if isinstance(node, ast.BoolOp):
            op = node.op
            for value in node.values:
                ret_op, ret_result = self.evaluate_tree(value, prof_storage, True)
                if result is None:
                    result = ret_result
                else:
                    if isinstance(op, ast.And):
                        result = result and ret_result
                    else:
                        result = result or ret_result
            return op, result
        elif isinstance(node, ast.UnaryOp):
            if not isinstance(node.op, ast.Not):
                raise AppArmorBug('Invalid unary operation in %s' % (self.__class__.__name__))
            result = not self.evaluate_tree(node.operand, prof_storage, True)
            return node.op, result
        elif isinstance(node, ast.Constant):
            val = quote_if_needed(strip_quotes(node.value))  # strip first because it can be quoted but not need it
            term = Term.create_instance(val)
            if resolve:
                cond = BooleanCondition('', term)
                result = cond.evaluate(prof_storage)
            return term, result
        elif isinstance(node, ast.Name):
            return node.id, result
        elif isinstance(node, ast.Call):
            func, noop = self.evaluate_tree(node.func, prof_storage)
            if func != 'defined':
                raise AppArmorBug('Invalid function name in %s' % (self.__class__.__name__))
            # there should be only one arg
            variable, noop = self.evaluate_tree(node.args[0], prof_storage)
            cond = BooleanCondition(func, variable)
            return 'defined', cond.evaluate(prof_storage)
        elif isinstance(node, ast.Compare):
            left, noop = self.evaluate_tree(node.left, prof_storage)
            right, noop = self.evaluate_tree(node.comparators[0], prof_storage)
            op = self.astcomp_to_string[type(node.ops[0])]
            cond = CompareCondition(left, op, right)
            return 'cmp', cond.evaluate(prof_storage)
        else:
            raise AppArmorBug('Unsupported node type in %s' % (self.__class__.__name__))

    def compare_ast(self, node1, node2):
        if type(node1) is not type(node2):
            return False
        if isinstance(node1, ast.AST):
            for k, v in vars(node1).items():
                if k in ('lineno', 'col_offset', 'ctx', 'end_lineno', 'end_col_offset'):
                    continue
                if not self.compare_ast(v, getattr(node2, k)):
                    return False
            return True
        elif isinstance(node1, list):
            if len(node1) != len(node2):
                return False
            for i in range(len(node1)):
                if not self.compare_ast(node1[i], node2[i]):
                    return False
            return True
        else:
            return node1 == node2

    def is_equal(self, other_tree):
        return self.compare_ast(self.tree, other_tree.tree)

    def transform_cond(self, text):
        """Used to transform policy conditional into Python format, so ast can be used"""

        def boolean_op(match):
            not_op = match.group('boolean_not')
            defined = match.group('defined')
            var = match.group('var')
            var = '"%s"' % (var)
            if defined:
                var = 'defined(%s)' % (var)
            return '%s%s' % (not_op, var)

        def compare_op(match):
            not_op = match.group('compare_not')
            left = match.group('left')
            op = match.group('op')
            right = match.group('right')

            if match.group('id_left') and not (left.startswith('"') or left.endswith('"')):
                left = '"%s"' % (left)
            if match.group('id_right') and not (right.startswith('"') or right.endswith('"')):
                right = '"%s"' % (right)

            return '%s%s %s %s' % (not_op, left, op, right)

        replaced = re.sub(RE_BOOLEAN_OP % {'term': ''}, boolean_op, text)
        replaced = re.sub(RE_COMPARE_OP_QUOTED % {'term': ''}, compare_op, replaced)
        return replaced


class Term():
    match_re = re.compile(RE_ID_OR_VAR % {'label': ''})

    @classmethod
    def create_instance(cls, raw_term):
        """parse raw_term and return instance of this class"""
        matches = cls.match_re.search(raw_term)
        if not matches:
            raise AppArmorBug('Unable to parse term in %s' % (cls.__class__.__name__))
        if matches.group('id'):
            return Id(matches.group('id'))
        else:
            var_type = matches.group('var_type')
            varname = matches.group('varname')
            var = matches.group('var')
            return Variable(var_type, varname, var)


class Variable(Term):
    def __init__(self, var_type, varname, var):
        self.varname = varname
        self.var = var
        if var_type == '$':
            self.var_type = 'boolean'
        else:
            self.var_type = 'variable'

    def get_variable_rule(self, prof_storage):
        for rule in prof_storage[self.var_type].rules:
            filtered = RE_ALL_VARIABLES.search(rule.varname)
            if self.varname == filtered.group('varname'):
                return rule
        return None

    def get_set(self, prof_storage):
        variable_rule = self.get_variable_rule(prof_storage)
        if variable_rule is None:
            raise AppArmorException(_('Error retrieving variable %(var)s') % {'var': self.var})
        return variable_rule.values

    def __repr__(self):
        return self.var


class Id(Term):
    def __init__(self, value):
        self.value = value

    def get_set(self, prof_storage):
        return {self.value}

    def __repr__(self):
        return self.value


class BooleanCondition():
    def __init__(self, defined: str, variable: Term):
        if not isinstance(defined, str):
            raise AppArmorBug('Passed invalid defined value to %s: %s' % (self.__class__.__name__, defined))
        if not isinstance(variable, Term):
            raise AppArmorBug('Passed invalid variable type to %s: %s' % (self.__class__.__name__, type(variable)))

        self.defined = defined
        self.variable = variable

    def evaluate(self, prof_storage):
        matched = self.variable.get_variable_rule(prof_storage)

        if not self.defined:  # boolean op
            if self.variable.var_type == 'boolean':
                if matched:
                    return matched.value
                else:
                    raise AppArmorException(_('Cannot find previous declaration of %(var)s') % {'var': self.variable})
            else:
                raise AppArmorException(_('Unexpected variable in boolean operation: %(var)s') % {'var': self.variable})
        else:
            return bool(matched)


class CompareCondition():
    valid_ops = ['==', '!=', 'in', '>', '>=', '<', '<=']

    def __init__(self, left_term: Term, op: str, right_term: Term):
        if op not in self.valid_ops:
            raise AppArmorBug('Passed invalid op value to %s: %s' % (self.__class__.__name__, op))
        if not isinstance(left_term, Term):
            raise AppArmorBug('Passed invalid left term type to %s: %s' % (self.__class__.__name__, type(left_term)))
        if not isinstance(right_term, Term):
            raise AppArmorBug('Passed invalid right term type to %s: %s' % (self.__class__.__name__, type(right_term)))

        self.left_term = left_term
        self.op = op
        self.right_term = right_term

    def compare(self, op, lhs, rhs):
        if type(lhs) is not type(rhs):
            raise AppArmorBug('Trying to compare elements of different types in %s' % (self.__class__.__name__))

        if (op == '>'):
            return lhs > rhs
        elif (op == '>='):
            return lhs >= rhs
        elif (op == '<'):
            return lhs < rhs
        elif (op == '<='):
            return lhs <= rhs
        else:
            raise AppArmorBug('Invalid op in %s: %s' % (self.__class__.__name__, op))

    def evaluate(self, prof_storage):
        lhs = self.left_term.get_set(prof_storage)
        rhs = self.right_term.get_set(prof_storage)

        if not isinstance(lhs, set) or not isinstance(rhs, set):
            raise AppArmorBug('Passed invalid type for condition term in %s' % (self.__class__.__name__))

        converted_lhs = None
        converted_rhs = None

        if self.op == 'in':
            return lhs.issubset(rhs)
        elif self.op == '==':
            return lhs == rhs
        elif self.op == '!=':
            return lhs != rhs

        try:
            if len(lhs) == 1:
                converted_lhs = int(next(iter(lhs)))
        except ValueError:
            pass

        try:
            if len(rhs) == 1:
                converted_rhs = int(next(iter(rhs)))
        except ValueError:
            pass

        if converted_lhs is None and converted_rhs is None:  # sets
            return self.compare(self.op, lhs, rhs)
        elif converted_lhs is not None and converted_rhs is not None:  # numbers
            return self.compare(self.op, converted_lhs, converted_rhs)
        else:
            raise AppArmorException(_('Can only compare numbers with numbers'))
