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

import argparse
import datetime
import fnmatch
import os
import os.path
import re
import shlex
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

def repo_gitdaemon_path(ctx, repo):
    return os.path.join(ctx['daemondir'], repo.id.lstrip('/'))

def repo_from_conf(repo, conf):
    for r in conf.repos:
        if r.id == gitdepot.parser.repo_id_normalize(repo):
            return r

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
    if error is None:
        return None
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
                if fnmatch.fnmatch(ref, p):
                    ref = os.path.relpath(os.path.join(root, f), refs_path)
                    refs.append(ref)
    return refs

def copy_repo(ctx, path, perms):
    r = tempfile.mkdtemp(prefix='repo-', dir=ctx['tmpdir'])
    init_repo(r)
    shutil.copyfile(os.path.join(path, 'description'), os.path.join(r, 'description'))
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
           'daemondir': os.path.join(base, 'daemon'),
           'rmdir': os.path.join(base, 'removed'),
           'checkout': os.path.join(base, 'gitdepot'),
           'auth': os.path.join(base, 'authorized_keys'),
           'conf': os.path.join(base, 'gitdepot.conf'),
          }
    return ctx

def fingerprint(ctx, key):
    keys = tempfile.NamedTemporaryFile(prefix='keys-', dir=ctx['tmpdir'], delete=False)
    keys.write(key.encode('ascii'))
    keys.flush()
    out = run_command(('ssh-keygen', '-l', '-f', keys.name),
                      InvalidKeyError,
                      shell=False,
                      stdin=open('/dev/null', 'r'),
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
        os.makedirs(ctx['rmdir'])
        fingerprint(ctx, key)
        conf = tempfile.NamedTemporaryFile(prefix='conf-', dir=ctx['tmpdir'], delete=False)
        conf.write('''user {0}
repo meta:
    grant {0} write access
'''.format(user).encode('utf8'))
        conf.flush()
        gitdepot.parser.parse(conf.name)
        path = os.path.join(ctx['repodir'], 'meta')
        init_repo(path)
        with open(os.path.join(path, 'description'), 'w') as f:
            f.write('gitdepot meta repo')
            f.flush()
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
        update_hook(ctx)
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
        arg = arg.strip("'")
    if action not in ('upload-pack', 'upload-archive', 'receive-pack'):
        raise UnknownCommandError()
    repo = repo_from_conf(arg, conf)
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
        assert shlex.quote(path) == path
        newcmd = "git {0} '{1}'".format(action, path)
        subprocess.check_call(['git', 'shell', '-c', newcmd], shell=False)
    finally:
        if erase is not None:
            shutil.rmtree(erase)

def set_hook(ctx, repo, hook, sh):
    assert hook in ('update', 'post-update', 'post-receive',)
    path = repo_absolute_path(ctx, repo)
    path = os.path.join(path, 'hooks', hook)
    assert os.path.exists(os.path.dirname(path))
    tmp = tempfile.NamedTemporaryFile(prefix='hook-', dir=ctx['tmpdir'], delete=False)
    tmp.write(sh.encode('ascii'))
    tmp.flush()
    os.chmod(tmp.name, stat.S_IRWXU)
    os.rename(tmp.name, path)

def install_ssh_keys(ctx):
    sshdir = os.path.expanduser('~/.ssh')
    if not os.path.exists(sshdir):
        os.makedirs(sshdir)
    authfile = os.path.expanduser('~/.ssh/authorized_keys')
    if os.path.exists(authfile):
        text = open(authfile).read()
    else:
        text = ''
    auth = open(ctx['auth']).read().strip()
    if not auth.endswith('\n'):
        auth += '\n'
    START = '# begin gitdepot keys\n'
    END = '# end gitdepot keys\n'
    if START not in text:
        out = text + START + auth + END
    else:
        head, tail = text.split(START)
        body, tail = tail.split(END)
        last_line = body.rsplit('\n')[-1]
        out = head + START + auth + END + tail
    new = tempfile.NamedTemporaryFile(prefix='gitdepot-',
            dir=os.path.expanduser('~/.ssh'), delete=False)
    new.write(out.encode('ascii'))
    new.flush()
    os.rename(new.name, authfile)

def update_hook(ctx):
    if 'GIT_DIR' in os.environ:
        del os.environ['GIT_DIR']
    if not os.path.exists(ctx['checkout']):
        run_command(('git', 'clone', os.path.join(ctx['repodir'], 'meta'), ctx['checkout']),
                    CouldNotInitializeRepoError,
                    shell=False,
                    stdin=open('/dev/null', 'r'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
    else:
        run_command(('git', 'fetch', os.path.join(ctx['repodir'], 'meta'), 'master'),
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
        keyfilename = os.path.join(ctx['checkout'], user.id + '.keys')
        if not os.path.exists(keyfilename):
            continue
        keyfile = open(keyfilename)
        for line in keyfile:
            key = line.strip()
            fp = fingerprint(ctx, key)
            authline = 'command="gitdepot --base {0} serve {1}",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding {2}\n'
            authline = authline.format(ctx['basedir'], user.id, key)
            auth.write(authline.encode('ascii'))
    auth.flush()
    for repo in conf.repos:
        git_daemon(ctx, conf, repo)
        path = repo_absolute_path(ctx, repo)
        if not os.path.exists(path):
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            init_repo(path)
            with open(os.path.join(path, 'description'), 'w') as f:
                description = repo.id
                for k, v in repo.config:
                    if k == 'description':
                        description = v
                f.write(description)
                f.flush()
        for k, v in repo.config:
            run_command(('git', 'config', k, v), CouldNotInitializeRepoError,
                        cwd=path,
                        shell=False,
                        stdin=open('/dev/null', 'r'),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)
        if repo.id == '/meta':
            set_hook(ctx, repo, 'post-update', '''#!/bin/sh
gitdepot --base {0} update-hook $@
git gc --auto --quiet
git update-server-info
'''.format(ctx['basedir']))
        else:
            set_hook(ctx, repo, 'post-update', '''#!/bin/sh
gitdepot --base {0} git-daemon {1}
git gc --auto --quiet
git update-server-info
'''.format(ctx['basedir'], repo.id))
        set_hook(ctx, repo, 'update', '''#!/bin/sh
gitdepot --base {0} permissions-check {1} $@
'''.format(ctx['basedir'], repo.id))
        if repo.hooks:
            assert all([h.hook == 'post-receive' for h in repo.hooks])
            hook = '#!/bin/sh\n'
            for h in repo.hooks:
                s = os.path.join(ctx['checkout'], h.script.lstrip('/'))
                hook += '{0} {1}\n'.format(s, ' '.join([shlex.quote(a) for a in h.args]))
            set_hook(ctx, repo, 'post-receive', hook)
    ids = set([r.id for r in conf.repos])
    for (d, ds, fs) in os.walk(ctx['repodir']):
        if 'config' not in fs:
            continue
        repo_id = '/' + os.path.relpath(d, ctx['repodir'])
        if repo_id in ids:
            continue
        rm_id = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        rm_id += repo_id.replace('/', '_')
        os.renames(d, os.path.join(ctx['rmdir'], rm_id))
    for (d, ds, fs) in os.walk(ctx['daemondir']):
        for f in ds + fs:
            p = os.path.join(d, f)
            repo_id = '/' + os.path.relpath(p, ctx['daemondir'])
            if repo_id in ids:
                continue
            if os.path.islink(p):
                os.unlink(p)
    shutil.copyfile(new_conf_path, ctx['conf'])
    shutil.copyfile(auth.name, ctx['auth'])
    os.unlink(auth.name)
    install_ssh_keys(ctx)

def git_daemon(ctx, conf, repo):
    if not isinstance(repo, gitdepot.parser.Repo):
        repo = repo_from_conf(repo, conf)
    if repo is None:
        sys.exit(1)
    P = relevant_principals(conf, 'public')
    perms = [p for p in repo.permissions if p.entity in P]
    if not perms:
        return 0
    p1 = repo_absolute_path(ctx, repo)
    p2 = repo_gitdaemon_path(ctx, repo)
    p3 = copy_repo(ctx, p1, perms)
    f = open(os.path.join(p3, "git-daemon-export-ok"), 'w')
    f.flush()
    f.close()
    if os.path.exists(p2):
        os.unlink(p2)
    if not os.path.exists(os.path.dirname(p2)):
        os.makedirs(os.path.dirname(p2))
    os.symlink(p3, p2)

def permissions_check(ctx, conf, repo, ref, old, new):
    if 'GITDEPOT_PRINCIPAL' not in os.environ:
        sys.exit(1)
    if not isinstance(repo, gitdepot.parser.Repo):
        repo = repo_from_conf(repo, conf)
    if repo is None:
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
    os.umask(0o077)
    parser = argparse.ArgumentParser(prog='gitdepot')
    parser.add_argument('--base', type=str, default='~',
                        help='socket to talk to minion daemon (default: ~)')
    subparsers = parser.add_subparsers(help='tools', dest='action')
    p = subparsers.add_parser('init')
    p.add_argument('user', type=str)
    p = subparsers.add_parser('serve')
    p.add_argument('user', type=str)
    p = subparsers.add_parser('update-hook')
    p.add_argument('ref', type=str)
    p.add_argument('commits', type=str, nargs='*')
    p = subparsers.add_parser('git-daemon')
    p.add_argument('repo', type=str)
    p = subparsers.add_parser('permissions-check')
    p.add_argument('repo', type=str)
    p.add_argument('ref', type=str)
    p.add_argument('old', type=str)
    p.add_argument('new', type=str)
    args = parser.parse_args()
    ctx = create_context(os.path.expanduser(args.base))
    if args.action == 'init':
        sys.exit(init(args.base, args.user, sys.stdin.read()) or 0)
    os.chdir(ctx['basedir'])
    conf = gitdepot.parser.parse(ctx['conf'])
    if args.action == 'serve':
        cmd = os.environ.get('SSH_ORIGINAL_COMMAND', None)
        if cmd is None:
            sys.exit(1)
        sys.exit(serve(ctx, conf, args.user, cmd) or 0)
    if args.action == 'update-hook':
        sys.exit(update_hook(ctx) or 0)
    if args.action == 'git-daemon':
        sys.exit(git_daemon(ctx, conf, args.repo) or 0)
    if args.action == 'permissions-check':
        sys.exit(permissions_check(ctx, conf, args.repo, args.ref, args.old, args.new) or 0)

if __name__ == '__main__':
    main()
