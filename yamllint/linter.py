# -*- coding: utf-8 -*-
# Copyright (C) 2016 Adrien Vergé
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re

import yaml

from yamllint import parser


PROBLEM_LEVELS = {
    0: None,
    1: 'warning',
    2: 'error',
    None: 0,
    'warning': 1,
    'error': 2,
}


class LintProblem(object):
    """Represents a linting problem found by yamllint."""
    def __init__(self, line, column, desc='<no description>', rule=None):
        #: Line on which the problem was found (starting at 1)
        self.line = line
        #: Column on which the problem was found (starting at 1)
        self.column = column
        #: Human-readable description of the problem
        self.desc = desc
        #: Identifier of the rule that detected the problem
        self.rule = rule
        self.level = None

    @property
    def message(self):
        if self.rule is not None:
            return '{} ({})'.format(self.desc, self.rule)
        return self.desc

    def __eq__(self, other):
        return (self.line == other.line and
                self.column == other.column and
                self.rule == other.rule)

    def __lt__(self, other):
        return (self.line < other.line or
                (self.line == other.line and self.column < other.column))

    def __repr__(self):
        return '%d:%d: %s' % (self.line, self.column, self.message)


def get_cosmetic_problems(buffer, conf, filepath):
    token_rules, line_rules, comment_rules, all_problems = [], [], [], []

    rule_ids = conf.enabled_rules(filepath)
    for rule_id in rule_ids:
        if rule_id.TYPE == 'line':
            line_rules.append(rule_id)
        elif rule_id.TYPE == 'comment':
            comment_rules.append(rule_id)
        elif rule_id.TYPE == 'token':
            token_rules.append(rule_id)
    
    context = {rule_id.ID: {} for rule_id in token_rules}

    DISABLE_RE = re.compile(r'^# yamllint disable(?: rule:(\S+))*\s*$')
    DISABLE_LINE_RE = re.compile(r'^# yamllint disable-line(?: rule:(\S+))*\s*$')
    ENABLE_RE = re.compile(r'^# yamllint enable(?: rule:(\S+))*\s*$')


    class DisabledRulesTracker:
        def __init__(self, is_line=False):
            self.is_line = is_line
            self.disabled_rules = set()  # Set of rules currently disabled
            self.all_rules = {rule.ID for rule in rule_ids}

        def handle_directive(self, directive):
            # Check for and parse disable directives
            
            disable_match = DISABLE_RE.match(directive)
            enable_match = ENABLE_RE.match(directive)
            disable_line_match = DISABLE_LINE_RE.match(directive)
            
            if disable_line_match and self.is_line:
                self.handle_disable_directive(directive)
                return
            if disable_match:
                self.handle_disable_directive(directive)
            elif enable_match:
                self.handle_enable_directive(directive)
            
        def handle_disable_directive(self, directive):
            """Handles disabling rules based on the comment directive."""
            extracted = self.extract_rules(directive)
            if not extracted:
                self.disabled_rules = self.all_rules.copy()
            else:
                self.disabled_rules.update(r for r in extracted if r in self.all_rules)

        def handle_enable_directive(self, directive):
            """Handles enabling rules based on the comment directive."""
            extracted = self.extract_rules(directive)
            if not extracted:
                self.disabled_rules.clear()
            else:
                for r in extracted:
                    self.disabled_rules.discard(r)

        def extract_rules(self, directive):
            """Extracts rule IDs from the comment directive."""
            parts = directive.split(' rule:')
            # Return the list of rule IDs, ignore the first element as it's the directive part
            return [part.strip() for part in parts[1:]]
        def is_disabled_by_directive(self, problem):
            return problem.rule in self.disabled_rules
    disabled_rules_tracker, disabled_for_current_line, disable_for_next_line = DisabledRulesTracker(), DisabledRulesTracker(True), DisabledRulesTracker(True)
    
    for elem in parser.token_or_comment_or_line_generator(buffer):
        try:
            directive = str(elem)
        except UnicodeError:
            # If we fail to convert the element to a string, we won't use it in handle_directive
            continue
        if isinstance(elem, parser.Line):
            for rule in line_rules:
                for problem in rule.check(conf.rules.get(rule.ID, {}), elem):
                    problem.level = conf.rules.get(rule.ID, {}).get('level')
                    problem.rule = rule.ID
                    all_problems.append(problem)
            yield from (problem for problem in all_problems if not disabled_for_current_line.is_disabled_by_directive(problem) and not disabled_rules_tracker.is_disabled_by_directive(problem))
            disabled_for_current_line = disable_for_next_line
            disable_for_next_line = DisabledRulesTracker(True)
            all_problems = []        
        elif isinstance(elem, parser.Comment):
            for rule in comment_rules:
                for problem in rule.check(conf.rules.get(rule.ID, {}), elem):
                    problem.level = conf.rules.get(rule.ID, {}).get('level')
                    problem.rule = rule.ID
                    all_problems.append(problem)
            disabled_rules_tracker.handle_directive(directive)
            (disabled_for_current_line if elem.is_inline() else disable_for_next_line).handle_directive(directive)
        elif isinstance(elem, parser.Token):
            for rule in token_rules:
                for problem in rule.check(conf.rules.get(rule.ID, {}), elem.curr, elem.prev, elem.next, elem.nextnext, context[rule.ID]):
                    problem.level = conf.rules.get(rule.ID, {}).get('level')
                    problem.rule = rule.ID
                    all_problems.append(problem)


def get_syntax_error(buffer):
    try:
        list(yaml.parse(buffer, Loader=yaml.BaseLoader))
    except yaml.error.MarkedYAMLError as e:
        problem = LintProblem(e.problem_mark.line + 1,
                              e.problem_mark.column + 1,
                              'syntax error: ' + e.problem + ' (syntax)')
        problem.level = 'error'
        return problem


def _run(buffer, conf, filepath):
    assert hasattr(buffer, '__getitem__'), \
        '_run() argument must be a buffer, not a stream'

    first_line = next(parser.line_generator(buffer)).content
    if re.match(r'^#\s*yamllint disable-file\s*$', first_line):
        return

    # If the document contains a syntax error, save it and yield it at the
    # right line
    syntax_error = get_syntax_error(buffer)

    for problem in get_cosmetic_problems(buffer, conf, filepath):
        # Insert the syntax error (if any) at the right place...
        if (syntax_error and syntax_error.line <= problem.line and
                syntax_error.column <= problem.column):
            yield syntax_error

            # If there is already a yamllint error at the same place, discard
            # it as it is probably redundant (and maybe it's just a 'warning',
            # in which case the script won't even exit with a failure status).
            if (syntax_error.line == problem.line and
                    syntax_error.column == problem.column):
                syntax_error = None
                continue

            syntax_error = None

        yield problem

    if syntax_error:
        yield syntax_error


def run(input, conf, filepath=None):
    """Lints a YAML source.

    Returns a generator of LintProblem objects.

    :param input: buffer, string or stream to read from
    :param conf: yamllint configuration object
    """
    if conf.is_file_ignored(filepath):
        return ()

    if isinstance(input, (bytes, str)):
        return _run(input, conf, filepath)
    elif hasattr(input, 'read'):  # Python 2's file or Python 3's io.IOBase
        # We need to have everything in memory to parse correctly
        content = input.read()
        return _run(content, conf, filepath)
    else:
        raise TypeError('input should be a string or a stream')
