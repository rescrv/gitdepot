# Copyright (c) 2015, Robert Escriva
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of this project nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import collections
import functools
import os.path
import re

import ply.lex
import ply.yacc

# This indentation parser comes from Andrew Dalke's GardenSnake language, which
# he released into the public domain via
# http://creativecommons.org/licenses/publicdomain/

class ParseError(Exception): pass

# Structures

User = collections.namedtuple('User', ('name',))
Group = collections.namedtuple('Group', ('name',))
Repo = collections.namedtuple('Repo', ('name',))

# Tokens

reserved = {
    'user': 'USER',
    'group': 'GROUP',
    'repo': 'REPO',
}

tokens = (
    'COLON',
    'IDENTIFIER',
    'WS',
    'NEWLINE',
    'INDENT',
    'DEDENT',
) + tuple(reserved.values())

t_COLON = r':'

def t_IDENTIFIER(t):
    r'[a-zA-Z_][-a-zA-Z0-9_/.]*'
    t.type = reserved.get(t.value, 'IDENTIFIER')
    return t

def t_comment(t):
    r"[ ]*\043[^\n]*"  # \043 is '#'
    pass

def t_WS(t):
    r' [ ]+ '
    if t.lexer.at_line_start:
        return t

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")
    t.type = "NEWLINE"
    return t

def t_error(t):
    raise ParseError('%s:%d: syntax error near "%s"' %
                 (t.lexer.path, t.lexer.lineno, t.value[:20].strip()))

NO_INDENT = 0
MAY_INDENT = 1
MUST_INDENT = 2

def track_tokens_filter(lexer, tokens):
    lexer.at_line_start = at_line_start = True
    indent = NO_INDENT
    saw_colon = False
    for token in tokens:
        token.at_line_start = at_line_start
        if token.type == "COLON":
            at_line_start = False
            indent = MAY_INDENT
            token.must_indent = False
        elif token.type == "NEWLINE":
            at_line_start = True
            if indent == MAY_INDENT:
                indent = MUST_INDENT
            token.must_indent = False
        elif token.type == "WS":
            assert token.at_line_start == True
            at_line_start = True
            token.must_indent = False
        else:
            if indent == MUST_INDENT:
                token.must_indent = True
            else:
                token.must_indent = False
            at_line_start = False
            indent = NO_INDENT
        yield token
        lexer.at_line_start = at_line_start

def _new_token(type, lineno):
    tok = ply.lex.LexToken()
    tok.type = type
    tok.value = None
    tok.lineno = lineno
    tok.lexpos = -1
    return tok

def DEDENT(lineno):
    return _new_token("DEDENT", lineno)

def INDENT(lineno):
    return _new_token("INDENT", lineno)

def indentation_filter(tokens):
    levels = [0]
    token = None
    depth = 0
    prev_was_ws = False
    for token in tokens:
        if token.type == "WS":
            assert depth == 0
            depth = len(token.value)
            prev_was_ws = True
            continue
        if token.type == "NEWLINE":
            depth = 0
            if prev_was_ws or token.at_line_start:
                continue
            yield token
            continue
        prev_was_ws = False
        if token.must_indent:
            if not (depth > levels[-1]):
                raise IndentationError("expected an indented block")

            levels.append(depth)
            yield INDENT(token.lineno)
        elif token.at_line_start:
            if depth == levels[-1]:
                pass
            elif depth > levels[-1]:
                raise IndentationError("indentation increase but not in new block")
            else:
                try:
                    i = levels.index(depth)
                except ValueError:
                    raise IndentationError("inconsistent indentation")
                for _ in range(i+1, len(levels)):
                    yield DEDENT(token.lineno)
                    yield _new_token("NEWLINE", token.lineno)
                    levels.pop()
        yield token
    if len(levels) > 1:
        assert token is not None
        for _ in range(1, len(levels)):
            yield DEDENT(token.lineno)
    
def lexer_filter(lexer):
    tokens = iter(lexer.token, None)
    tokens = track_tokens_filter(lexer, tokens)
    for token in indentation_filter(tokens):
        yield token

class TokenFunc(object):

    def __init__(self, lexer):
        self.lexer = lexer
        self.token_stream = None
        self.done = False

    def __call__(self):
        if self.token_stream is None and not self.done:
            self.token_stream = lexer_filter(self.lexer)
        if self.token_stream is None:
            return None
        try:
            return next(self.token_stream)
        except StopIteration:
            self.token_stream = None
            self.done = True
            return None

# Grammar

def p_statements(t):
    '''
    stmts : stmts stmt
          | stmt
    '''
    if len(t) == 3:
        stmts = t[1]
        if t[2]:
            stmts.append(t[2])
        t[0] = stmts
    elif len(t) == 2:
        if t[1]:
            t[0] = [t[1]]
        else:
            t[0] = []
    else:
        assert False

def p_statement(t):
    '''
    stmt : user
         | group
         | repo
         | NEWLINE
    '''
    t[0] = t[1]

def p_user(t):
    '''
    user : USER IDENTIFIER NEWLINE
    '''
    t[0] = User(name=t[2])

def p_group(t):
    '''
    group : GROUP IDENTIFIER NEWLINE
    '''
    t[0] = Group(name=t[2])

def p_repo(t):
    '''
    repo : REPO IDENTIFIER NEWLINE
         | REPO IDENTIFIER COLON repo_suite
    '''
    t[0] = Repo(name=t[2])

def p_repo_suite(t):
    '''
    repo_suite : USER NEWLINE
               | NEWLINE INDENT stmt DEDENT
    '''
    t[0] = ()

def p_error(t):
    if t is None:
        raise ParseError('unexpected end of file')
    else:
        raise ParseError('%s:%d: syntax error near "%s"' %
                     (t.lexer.path, t.lexer.lineno, t.value[:20].strip()))

# Public Functions

def parse(filename):
    f = open(filename)
    contents = f.read()
    lexer = ply.lex.lex(reflags=re.UNICODE)
    lexer.path = filename
    lexer.file = os.path.basename(filename)
    lexer.lineno = 1
    lexer.expectstring = False
    lexer.git_users = set()
    lexer.git_groups = set()
    lexer.git_repos = set()
    tf = TokenFunc(lexer)
    parser = ply.yacc.yacc(debug=0, write_tables=0,
                           errorlog=ply.yacc.NullLogger())
    return parser.parse(contents, lexer=lexer, tokenfunc=tf)

print(parse("gitparsing.txt"))
