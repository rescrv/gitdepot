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

import fnmatch
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

import gitdepot.parser

class UnknownCommandError(Exception): pass
class UnknownRepositoryError(Exception): pass
class CouldNotInitializeRepoError(Exception): pass
class InvalidKeyError(Exception): pass

def repo_absolute_path(ctx, repo):
    return os.path.join(ctx['repodir'], repo.id.lstrip('/'))

def relevant_principals(conf, user):
    P = set()
    for u in conf.users:
        if u.id == user:
            P.add(u.id)
    for g in conf.groups:
        if set(g.members) & P:
            P.add(g.id)
    P.add('public')
    return P

def run_command(args, error, **kwargs):
    p = subprocess.Popen(args, **kwargs)
    out, err = p.communicate()
    if p.returncode != 0:
        raise error(out)
    return out

def init_repo(path):
    run_command(('git', 'init', '--bare', path),
                CouldNotInitializeRepoError,
                shell=False,
                stdin=open('/dev/null', 'r'),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)

def repo_refs(path, reftype, perms):
    refs_path = os.path.join(path, 'refs', reftype)
    refs = []
    patterns = []
    for p in perms:
        pattern = p.resource
        if not pattern.startswith('refs/'):
            pattern = 'refs/' + reftype + '/' + pattern
        patterns.append(pattern)
    for root, dirs, files in os.walk(refs_path):
        for f in files:
            ref = os.path.relpath(os.path.join(root, f), path)
            for p in patterns:
                if fnmatch.fnmatch(ref, pattern):
                    ref = os.path.relpath(os.path.join(root, f), refs_path)
                    refs.append(ref)
    return refs

def copy_repo(ctx, path, perms):
    r = tempfile.mkdtemp(prefix='repo-', dir=ctx['tmpdir'])
    init_repo(r)
    heads = repo_refs(path, 'heads', perms)
    tags = repo_refs(path, 'tags', perms)
    for head in heads:
        run_command(('git', 'fetch', path, 'refs/heads/' + head),
                    CouldNotInitializeRepoError,
                    cwd=r,
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
        run_command(('git', 'branch', head, 'FETCH_HEAD'),
                    CouldNotInitializeRepoError,
                    cwd=r,
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
    for tag in tags:
        run_command(('git', 'fetch', path, 'refs/tags/' + tag),
                    CouldNotInitializeRepoError,
                    cwd=r,
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
        run_command(('git', 'tag', tag, 'FETCH_HEAD'),
                    CouldNotInitializeRepoError,
                    cwd=r,
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
    return r

def create_context(base):
    base = os.path.abspath(base)
    ctx = {'basedir': base,
           'repodir': os.path.join(base, 'repos'),
           'tmpdir': os.path.join(base, 'tmp'),
           'checkout': os.path.join(base, 'gitdepot'),
           'auth': os.path.join(base, 'authorized_keys'),
           'conf': os.path.join(base, 'gitdepot.conf'),
          }
    return ctx

def fingerprint(ctx, key):
    keys = tempfile.NamedTemporaryFile(prefix='keys-', dir=ctx['tmpdir'], delete=False)
    keys.write(key.encode('ascii'))
    keys.flush()
    out = run_command(('ssh-keygen', '-l', '-f', '/dev/stdin'),
                      InvalidKeyError,
                      shell=False,
                      stdin=keys,
                      stdout=subprocess.PIPE,
                      stderr=subprocess.STDOUT)
    os.unlink(keys.name)
    pieces = out.split(None)
    fp = [p for p in pieces if p.startswith(b'SHA256')]
    return fp

def init(path, user, key):
    assert re.match('^' + gitdepot.parser.t_ATOM.__doc__ + '$', user)
    success = False
    path = os.path.abspath(path)
    ctx = create_context(path)
    os.makedirs(ctx['basedir'])
    try:
        os.makedirs(ctx['repodir'])
        os.makedirs(ctx['tmpdir'])
        fingerprint(ctx, key)
        conf = tempfile.NamedTemporaryFile(prefix='conf-', dir=ctx['tmpdir'], delete=False)
        conf.write('''user {0}
repo gitdepot:
    grant {0} write access
'''.format(user).encode('utf8'))
        conf.flush()
        gitdepot.parser.parse(conf.name)
        path = os.path.join(ctx['repodir'], 'gitdepot')
        init_repo(path)
        kwargs = {'cwd': path,
                  'shell': False,
                  'stdin': open('/dev/null', 'r'),
                  'stdout': subprocess.PIPE,
                  'stderr': subprocess.STDOUT}
        blob = run_command(('git', 'hash-object', '-w', conf.name),
                           CouldNotInitializeRepoError, **kwargs)
        os.unlink(conf.name)
        run_command(('git', 'update-index', '--add', '--cacheinfo', '100644', blob, 'gitdepot.conf'),
                    CouldNotInitializeRepoError, **kwargs)
        keys = tempfile.NamedTemporaryFile(prefix='keys-', dir=ctx['tmpdir'], delete=False)
        keys.write(key.encode('ascii'))
        keys.flush()
        blob = run_command(('git', 'hash-object', '-w', keys.name),
                           CouldNotInitializeRepoError, **kwargs)
        os.unlink(keys.name)
        run_command(('git', 'update-index', '--add', '--cacheinfo', '100644', blob.strip(), user + '.keys'),
                    CouldNotInitializeRepoError, **kwargs)
        tree = run_command(('git', 'write-tree'),
                           CouldNotInitializeRepoError, **kwargs)
        env = os.environ.copy()
        env['GIT_AUTHOR_NAME'] = 'gitdepot'
        env['GIT_AUTHOR_EMAIL'] = 'programmatically generated'
        env['GIT_COMMITTER_NAME'] = 'gitdepot'
        env['GIT_COMMITTER_EMAIL'] = 'programmatically generated'
        msg = tempfile.TemporaryFile(prefix='msg-', dir=ctx['tmpdir'])
        msg.write('gitdepot initial commit'.encode('ascii'))
        msg.flush()
        msg.seek(0)
        kwargs['env'] = env
        kwargs['stdin'] = msg
        commit = run_command(('git', 'commit-tree', tree.strip()),
                             CouldNotInitializeRepoError, **kwargs)
        del kwargs['env']
        kwargs['stdin'] = open('/dev/null', 'r')
        run_command(('git', 'update-ref', 'refs/heads/master', commit.strip()),
                    CouldNotInitializeRepoError, **kwargs)
        checkout_latest_gitdepot(ctx)
        success = True
    finally:
        if not success:
            shutil.rmtree(ctx['basedir'])

def serve(ctx, conf, user, cmd):
    if cmd.startswith('git-') or cmd.startswith('git '):
        cmd = cmd[4:]
    action = None
    arg = None
    if ' ' in cmd:
        action, arg = cmd.split(None, 1)
    if action not in ('upload-pack', 'upload-archive', 'receive-pack'):
        raise UnknownCommandError()
    repo = None
    for r in conf.repos:
        if r.id == gitdepot.parser.id_normalize(arg):
            repo = r
            break
    if repo is None:
        raise UnknownRepositoryError()
    P = relevant_principals(conf, user)
    path = repo_absolute_path(ctx, repo)
    erase = None
    try:
        if action in ('upload-pack', 'upload-archive'):
            perms = [p for p in repo.permissions if p.entity in P]
            # check must happen before creating the repo to avoid timing side
            # channel
            if perms is None:
                raise UnknownRepositoryError()
            path = erase = copy_repo(ctx, path, perms)
        elif action == 'receive-pack':
            perms = [p for p in repo.permissions
                     if p.entity in P and p.action == 'write']
            if perms is None:
                raise UnknownRepositoryError()
            assert os.path.exists(path)
        else:
            assert False
        # Now execute the git shell to do what we want
        os.environ['GITDEPOT_PRINCIPAL'] = user
        #subprocess.check_call(['git', 'shell', '-c', 'git', action, path], shell=False)
        # XXX
        print(['git', 'shell', '-c', 'git', action, path])
    finally:
        if erase is not None:
            shutil.rmtree(erase)

def set_hook(ctx, repo, hook, sh):
    assert hook in ('update', 'post-update',)
    path = repo_absolute_path(ctx, repo)
    path = os.path.join(path, 'hooks', hook)
    assert os.path.exists(os.path.dirname(path))
    tmp = tempfile.NamedTemporaryFile(prefix='hook-', dir=ctx['tmpdir'], delete=False)
    tmp.write(sh.encode('ascii'))
    tmp.flush()
    os.chmod(tmp.name, stat.S_IRWXU)
    os.rename(tmp.name, path)

def checkout_latest_gitdepot(ctx):
    if not os.path.exists(ctx['checkout']):
        run_command(('git', 'clone', os.path.join(ctx['repodir'], 'gitdepot'), ctx['checkout']),
                    CouldNotInitializeRepoError,
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
    else:
        run_command(('git', 'fetch', os.path.join(ctx['repodir'], 'gitdepot'), 'master'),
                    CouldNotInitializeRepoError,
                    cwd=ctx['checkout'],
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
        run_command(('git', 'reset', '--hard', 'FETCH_HEAD'),
                    CouldNotInitializeRepoError,
                    cwd=ctx['checkout'],
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
    new_conf_path = os.path.join(ctx['checkout'], 'gitdepot.conf')
    conf = gitdepot.parser.parse(new_conf_path)
    auth = tempfile.NamedTemporaryFile(prefix='auth-', dir=ctx['tmpdir'], delete=False)
    for user in conf.users:
        keyfile = open(os.path.join(ctx['checkout'], user.id + '.keys'))
        for line in keyfile:
            key = line.strip()
            fp = fingerprint(ctx, key)
            authline = 'command="gitdepot --base {0} serve {1}",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding {2}\n'
            authline = authline.format(ctx['basedir'], user.id, key)
            auth.write(authline.encode('ascii'))
    auth.flush()
    for repo in conf.repos:
        path = repo_absolute_path(ctx, repo)
        if not os.path.exists(path):
            if not os.path.exists(os.path.dirname(path)):
                os.path.makedirs(os.path.dirname(path))
            init_repo(path)
        if repo.id == '/gitdepot':
            set_hook(ctx, repo, 'post-update', '''#!/bin/sh
gitdepot --base {0} update-hook
'''.format(ctx['basedir']))
        set_hook(ctx, repo, 'update', '''#!/bin/sh
gitdepot --base {0} permissions-check $@
'''.format(ctx['basedir']))
    shutil.copyfile(new_conf_path, ctx['conf'])
    shutil.copyfile(auth.name, ctx['auth'])
    os.unlink(auth.name)

def permissions_check(ctx, conf, repo, ref, old, new):
    if 'GITDEPOT_PRINCIPAL' not in os.environ:
        sys.exit(1)
    P = relevant_principals(conf, os.environ['GITDEPOT_PRINCIPAL'])
    perms = [p for p in repo.permissions
             if p.entity in P and p.action == 'write']
    prefix = None
    if not ref.startswith('refs/heads/') and not ref.startswith('refs/tags/'):
        print('write access denied')
        sys.exit(1)
    elif ref.startswith('refs/heads/'):
        prefix = 'refs/heads/'
    elif ref.startswith('refs/tags/'):
        prefix = 'refs/tags/'
    else:
        assert False
    for p in perms:
        pattern = p.resource
        if not pattern.startswith('refs/'):
            pattern = prefix + pattern
        if fnmatch.fnmatch(ref, pattern):
            sys.exit(0)
    print('write access denied')
    sys.exit(1)

def main():
    ctx = create_context('.')
    os.chdir(ctx['basedir'])
    conf = gitdepot.parser.parse(ctx['conf'])
    #serve(ctx, conf, 'rescrv', 'upload-pack HyperDex')
    #os.environ['GITDEPOT_PRINCIPAL'] = 'rescrv'
    #hook_update(ctx, conf, conf.repos[0], 'refs/heads/master', "XX", "YY")

if __name__ == '__main__':
    #main()
    key = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvynRwEfgIjBxpOVKaZDBTT9JBK9XZi0YXCM4fFQ1/EaGIPPFB+41gYlTNcstluMUope7ue1bOsDjDfiVas+15YW4dkJLLOidl/VSaaGTMt0axM0x6SLcw0RGYeXvlOiSEdO9tNmz2vFgtCtV861b0EGu1SmkdQBHRkPAobwgYcE='
    init('somepath', 'rescrv', key)


"""
        cmd = os.environ.get('SSH_ORIGINAL_COMMAND', None)
        if cmd is None:
            main_log.error('Need SSH_ORIGINAL_COMMAND in environment.')
            sys.exit(1)
        os.chdir(os.path.expanduser('~'))

        try:
            newcmd = serve(
                cfg=cfg,
                user=user,
                command=cmd,
                )
        except ServingError, e:
            main_log.error('%s', e)
            sys.exit(1)

        main_log.debug('Serving %s', newcmd)
        os.environ['GITOSIS_USER'] = user
        os.execvp('git', ['git', 'shell', '-c', newcmd])
        main_log.error('Cannot execute git-shell.')
        sys.exit(1)
        '''
        """
