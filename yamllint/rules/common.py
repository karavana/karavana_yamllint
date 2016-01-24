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

import yaml

from yamllint.linter import LintProblem


def spaces_after(token, prev, next, min=-1, max=-1,
                 min_desc=None, max_desc=None):
    if next is not None and token.end_mark.line == next.start_mark.line:
        spaces = next.start_mark.pointer - token.end_mark.pointer
        if max != - 1 and spaces > max:
            return LintProblem(token.start_mark.line + 1,
                               next.start_mark.column, max_desc)
        elif min != - 1 and spaces < min:
            return LintProblem(token.start_mark.line + 1,
                               next.start_mark.column + 1, min_desc)


def spaces_before(token, prev, next, min=-1, max=-1,
                  min_desc=None, max_desc=None):
    if (prev is not None and prev.end_mark.line == token.start_mark.line and
            # Discard tokens (only scalars?) that end at the start of next line
            (prev.end_mark.pointer == 0 or
             prev.end_mark.buffer[prev.end_mark.pointer - 1] != '\n')):
        spaces = token.start_mark.pointer - prev.end_mark.pointer
        if max != - 1 and spaces > max:
            return LintProblem(token.start_mark.line + 1,
                               token.start_mark.column, max_desc)
        elif min != - 1 and spaces < min:
            return LintProblem(token.start_mark.line + 1,
                               token.start_mark.column + 1, min_desc)


class Comment(object):
    def __init__(self, line, column, buffer, pointer):
        self.line = line
        self.column = column
        self.buffer = buffer
        self.pointer = pointer

    def __repr__(self):
        end = self.buffer.find('\n', self.pointer)
        if end == -1:
            end = self.buffer.find('\0', self.pointer)
        if end != -1:
            return self.buffer[self.pointer:end]
        return self.buffer[self.pointer:]

    def __eq__(self, other):
        return (self.line == other.line and
                self.column == other.column and
                str(self) == str(other))


def get_line_indent(token):
    """Finds the indent of the line the token starts in."""
    start = token.start_mark.buffer.rfind('\n', 0,
                                          token.start_mark.pointer) + 1
    content = start
    while token.start_mark.buffer[content] == ' ':
        content += 1
    return content - start


def get_comments_between_tokens(token1, token2, skip_first_line=False):
    if token2 is None:
        buf = token1.end_mark.buffer[token1.end_mark.pointer:]
    elif (token1.end_mark.line == token2.start_mark.line and
          not isinstance(token1, yaml.StreamStartToken) and
          not isinstance(token2, yaml.StreamEndToken)):
        return
    else:
        buf = token1.end_mark.buffer[token1.end_mark.pointer:
                                     token2.start_mark.pointer]

    line_no = token1.end_mark.line + 1
    column_no = token1.end_mark.column + 1
    pointer = token1.end_mark.pointer

    for line in buf.split('\n'):
        if skip_first_line:
            skip_first_line = False
        else:
            pos = line.find('#')
            if pos != -1:
                yield Comment(line_no, column_no + pos,
                              token1.end_mark.buffer, pointer + pos)

        pointer += len(line) + 1
        line_no += 1
        column_no = 1


def is_explicit_key(token):
    # explicit key:
    #   ? key
    #   : v
    # or
    #   ?
    #     key
    #   : v
    return (token.start_mark.pointer < token.end_mark.pointer and
            token.start_mark.buffer[token.start_mark.pointer] == '?')