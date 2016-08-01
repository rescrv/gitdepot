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

def write_description(repo, description):
    with open(os.path.join(repo, 'description'), 'w') as f:
        f.write(description)
        f.flush()

class GitDepot:

    def __init__(self, base, home=None):
        self._home = os.path.abspath(home or os.path.expanduser('~'))
        self._base = os.path.abspath(base)
        self.conf = None
        if os.path.exists(self.CONF):
            self.conf = gitdepot.parser.parse(self.CONF)

    @property
    def HOMEDIR(self):
        return self._home

    @property
    def BASEDIR(self):
        return self._base

    @property
    def REPODIR(self):
        return os.path.join(self._base, 'repos')

    @property
    def META_REPO(self):
        return os.path.join(self.REPODIR, 'meta')

    @property
    def TMPDIR(self):
        return os.path.join(self._base, 'tmp')

    @property
    def DAEMONDIR(self):
        return os.path.join(self._base, 'daemon')

    @property
    def RMDIR(self):
        return os.path.join(self._base, 'removed')

    @property
    def CHECKOUT(self):
        return os.path.join(self._base, 'gitdepot')

    @property
    def AUTH(self):
        return os.path.join(self._base, 'authorized_keys')

    @property
    def CONF(self):
        return os.path.join(self._base, 'gitdepot.conf')

    def init(self, user, key):
        assert re.match('^' + gitdepot.parser.t_ATOM.__doc__ + '$', user)
        success = False
        os.makedirs(self.BASEDIR)
        try:
            os.makedirs(self.REPODIR)
            os.makedirs(self.TMPDIR)
            os.makedirs(self.RMDIR)
            # check that the key parses before we do anything
            self.fingerprint(key)
            # write the config file
            conf = tempfile.NamedTemporaryFile(prefix='conf-', dir=self.TMPDIR, delete=False)
            conf.write('''user {0}
repo meta:
    grant {0} write access
'''.format(user).encode('utf8'))
            conf.flush()
            # check that the conf file we just wrote parses
            self.conf = gitdepot.parser.parse(conf.name)
            init_repo(self.META_REPO)
            write_description(self.META_REPO, 'gitdepot meta repo')
            kwargs = {'cwd': self.META_REPO,
                      'shell': False,
                      'stdin': open('/dev/null', 'r'),
                      'stdout': subprocess.PIPE,
                      'stderr': subprocess.STDOUT}
            blob = run_command(('git', 'hash-object', '-w', conf.name),
                               CouldNotInitializeRepoError, **kwargs)
            os.unlink(conf.name)
            run_command(('git', 'update-index', '--add', '--cacheinfo', '100644', blob, 'gitdepot.conf'),
                        CouldNotInitializeRepoError, **kwargs)
            keys = tempfile.NamedTemporaryFile(prefix='keys-', dir=self.TMPDIR, delete=False)
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
            msg = tempfile.TemporaryFile(prefix='msg-', dir=self.TMPDIR)
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
            self.update_hook()
            success = True
        finally:
            if not success:
                shutil.rmtree(self.BASEDIR)

    def serve(self, user, cmd):
        assert self.conf
        if cmd.startswith('git-') or cmd.startswith('git '):
            cmd = cmd[4:]
        action = None
        arg = None
        if ' ' in cmd:
            action, arg = cmd.split(None, 1)
            arg = arg.strip("'")
        if action not in ('upload-pack', 'upload-archive', 'receive-pack'):
            raise UnknownCommandError()
        repo = self.get_repo(arg)
        if repo is None:
            raise UnknownRepositoryError()
        P = self.get_principals(user)
        path = self.get_repo_path(repo.id)
        erase = None
        try:
            if action in ('upload-pack', 'upload-archive'):
                perms = [p for p in repo.permissions if p.entity in P]
                # check must happen before creating the repo to avoid timing side
                # channel
                if perms is None:
                    raise UnknownRepositoryError()
                # XXX we don't need to copy this here if the user has
                # unrestricted access
                path = erase = self.copy_repo(path, perms)
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

    def update_hook(self):
        if 'GIT_DIR' in os.environ:
            del os.environ['GIT_DIR']
        self.update_meta_checkout()
        new_conf_path = os.path.join(self.CHECKOUT, 'gitdepot.conf')
        new_auth_file = self.write_temporary_auth()
        # switch to the new configuration
        self.conf = gitdepot.parser.parse(new_conf_path)
        self.clean_repodir()
        self.clean_daemondir()
        for repo in self.conf.repos:
            self.git_daemon(repo.id)
            path = self.get_repo_path(repo.id)
            if not os.path.exists(path):
                self.create_repo(repo)
            for k, v in repo.config:
                run_command(('git', 'config', k, v), CouldNotInitializeRepoError,
                            cwd=path,
                            shell=False,
                            stdin=open('/dev/null', 'r'),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
            if repo.id == 'meta':
                self.set_hook(repo, 'post-update', '''#!/bin/sh
gitdepot --base {0} --home {1} update-hook $@
git gc --auto --quiet
git update-server-info
'''.format(self.BASEDIR, self.HOMEDIR))
            else:
                self.set_hook(repo, 'post-update', '''#!/bin/sh
gitdepot --base {0} --home {1} git-daemon {2}
git gc --auto --quiet
git update-server-info
'''.format(self.BASEDIR, self.HOMEDIR, repo.id))
            self.set_hook(repo, 'update', '''#!/bin/sh
gitdepot --base {0} --base {1} permissions-check {2} $@
'''.format(self.BASEDIR, self.HOMEDIR, repo.id))
            if repo.hooks:
                assert all([h.hook == 'post-receive' for h in repo.hooks])
                hook = '#!/bin/sh\n'
                for h in repo.hooks:
                    s = os.path.join(self.CHECKOUT, h.script.lstrip('/'))
                    hook += '{0} {1}\n'.format(s, ' '.join([shlex.quote(a) for a in h.args]))
                self.set_hook(repo, 'post-receive', hook)
        shutil.copyfile(new_conf_path, self.CONF)
        shutil.copyfile(new_auth_file.name, self.AUTH)
        os.unlink(new_auth_file.name)
        self.install_ssh_keys()

    def update_meta_checkout(self):
        kwargs = {'shell': False,
                  'stdin': open('/dev/null', 'r'),
                  'stdout': subprocess.PIPE,
                  'stderr': subprocess.STDOUT}
        if not os.path.exists(self.CHECKOUT):
            run_command(('git', 'clone', self.META_REPO, self.CHECKOUT),
                        CouldNotInitializeRepoError, **kwargs)
        else:
            run_command(('git', 'fetch', self.META_REPO, 'master'),
                        CouldNotInitializeRepoError,
                        cwd=self.CHECKOUT, **kwargs)
            run_command(('git', 'reset', '--hard', 'FETCH_HEAD'),
                        CouldNotInitializeRepoError,
                        cwd=self.CHECKOUT, **kwargs)

    def clean_repodir(self):
        ids = set([r.id for r in self.conf.repos])
        for (d, ds, fs) in os.walk(self.REPODIR):
            if 'config' not in fs:
                continue
            repo_id = os.path.relpath(d, self.REPODIR)
            if repo_id in ids:
                continue
            rm_id = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
            rm_id += repo_id.replace('/', '_')
            os.renames(d, os.path.join(self.RMDIR, rm_id))
        self.clean_empty_dirs(self.REPODIR)

    def clean_daemondir(self):
        ids = set([r.id for r in self.conf.repos])
        for (d, ds, fs) in os.walk(self.DAEMONDIR):
            for f in ds + fs:
                p = os.path.join(d, f)
                repo_id = os.path.relpath(p, self.DAEMONDIR)
                if repo_id in ids:
                    continue
                if os.path.islink(p):
                    os.unlink(p)
        self.clean_empty_dirs(self.DAEMONDIR)

    def clean_empty_dirs(self, root):
        did_work = True
        while did_work:
            did_work = False
            # topdown=False won't help here as lists are generated before
            # traversing a subdirectory and won't see the rm
            for (d, ds, fs) in os.walk(root):
                if not ds and not fs and d != root:
                    did_work=True
                    os.rmdir(d)

    def create_repo(self, repo):
        path = self.get_repo_path(repo.id)
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
            init_repo(path)
            description = repo.id
            for k, v in repo.config:
                if k == 'description':
                    description = v
            write_description(path, description)

    def set_hook(self, repo, hook, sh):
        assert hook in ('update', 'post-update', 'post-receive',)
        path = self.get_repo_path(repo.id)
        path = os.path.join(path, 'hooks', hook)
        assert os.path.exists(os.path.dirname(path))
        tmp = tempfile.NamedTemporaryFile(prefix='hook-', dir=self.TMPDIR, delete=False)
        tmp.write(sh.encode('ascii'))
        tmp.flush()
        os.chmod(tmp.name, stat.S_IRWXU)
        os.rename(tmp.name, path)

    def git_daemon(self, repo):
        repo = self.get_repo(repo)
        if repo is None:
            sys.exit(1)
        P = self.get_principals('public')
        perms = [p for p in repo.permissions if p.entity in P]
        if not perms:
            return 0
        p1 = self.get_repo_path(repo.id)
        p2 = self.get_daemon_path(repo.id)
        p3 = self.copy_repo(p1, perms, prefix='daemon-')
        f = open(os.path.join(p3, "git-daemon-export-ok"), 'w')
        f.flush()
        f.close()
        if os.path.exists(p2):
            old = os.path.join(os.path.dirname(p2), os.readlink(p2))
            shutil.rmtree(old)
        if os.path.lexists(p2):
            os.unlink(p2)
        if not os.path.exists(os.path.dirname(p2)):
            os.makedirs(os.path.dirname(p2))
        os.symlink(p3, p2)

    def permissions_check(self, repo, ref, old, new):
        if self.conf is None:
            sys.exit(1)
        if 'GITDEPOT_PRINCIPAL' not in os.environ:
            sys.exit(1)
        repo = self.get_repo(repo)
        if repo is None:
            sys.exit(1)
        P = self.get_principals(os.environ['GITDEPOT_PRINCIPAL'])
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

    def fingerprint(self, key):
        keys = tempfile.NamedTemporaryFile(prefix='keys-', dir=self.TMPDIR, delete=False)
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

    def get_repo(self, name):
        name = gitdepot.parser.id_normalize(name)
        for r in self.conf.repos:
            if r.id == name:
                return r

    def get_principals(self, user):
        P = set()
        for u in self.conf.users:
            if u.id == user:
                P.add(u.id)
        P.add('public')
        num = len(P) - 1
        while num != len(P):
            for g in self.conf.groups:
                if set(g.members) & P:
                    P.add(g.id)
            num = len(P)
        return P

    def get_repo_path(self, repo_id):
        return os.path.join(self.REPODIR, repo_id)

    def get_daemon_path(self, repo_id):
        return os.path.join(self.DAEMONDIR, repo_id)

    def copy_repo(self, path, perms, prefix='clone-', dirname=None):
        dirname = dirname or self.TMPDIR
        r = tempfile.mkdtemp(prefix=prefix, dir=dirname)
        erase = True
        try:
            init_repo(r)
            shutil.copyfile(os.path.join(path, 'description'), os.path.join(r, 'description'))
            heads = repo_refs(path, 'heads', perms)
            tags = repo_refs(path, 'tags', perms)
            kwargs = {'cwd': r,
                      'shell': False,
                      'stdin': open('/dev/null', 'r'),
                      'stdout': subprocess.PIPE,
                      'stderr': subprocess.STDOUT}
            for head in heads:
                run_command(('git', 'fetch', path, 'refs/heads/' + head),
                            CouldNotInitializeRepoError, **kwargs)
                run_command(('git', 'branch', head, 'FETCH_HEAD'),
                            CouldNotInitializeRepoError, **kwargs)
            for tag in tags:
                run_command(('git', 'fetch', path, 'refs/tags/' + tag),
                            CouldNotInitializeRepoError, **kwargs)
                run_command(('git', 'tag', tag, 'FETCH_HEAD'),
                            CouldNotInitializeRepoError, **kwargs)
            erase = False
            return r
        finally:
            if erase:
                shutil.rmtree(r)

    def write_temporary_auth(self):
        auth = tempfile.NamedTemporaryFile(prefix='auth-', dir=self.TMPDIR, delete=False)
        for user in self.conf.users:
            keyfilename = os.path.join(self.CHECKOUT, user.id + '.keys')
            if not os.path.exists(keyfilename):
                continue
            keyfile = open(keyfilename)
            for line in keyfile:
                key = line.strip()
                fp = self.fingerprint(key)
                authline = 'command="gitdepot --base {0} --home {1} serve {2}",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding {3}\n'
                authline = authline.format(shlex.quote(self.BASEDIR),
                                           shlex.quote(self.HOMEDIR),
                                           user.id, key)
                auth.write(authline.encode('ascii'))
        auth.flush()
        return auth

    def install_ssh_keys(self):
        sshdir = os.path.join(self.HOMEDIR, '.ssh')
        if not os.path.exists(sshdir):
            os.makedirs(sshdir)
            os.chmod(sshdir, stat.S_IRWXU)
        authfile = os.path.join(sshdir, 'authorized_keys')
        if os.path.exists(authfile):
            text = open(authfile).read()
        else:
            text = ''
        auth = open(self.AUTH).read().strip()
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
                                          dir=sshdir, delete=False)
        new.write(out.encode('ascii'))
        new.flush()
        os.chmod(new.name, stat.S_IRUSR | stat.S_IWUSR)
        os.rename(new.name, authfile)

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(prog='gitdepot')
    parser.add_argument('--home', type=str, default='~',
                        help='directory to treat as the user home directory (default: ~)')
    parser.add_argument('--base', type=str, default=None,
                        help='directory containing all of gitdepot (default: --home/depot')
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
    home = os.path.expanduser(args.home)
    base = os.path.join(home, 'depot') if args.base is None else args.base
    gd = GitDepot(base, home)
    if args.action == 'init':
        sys.exit(gd.init(args.user, sys.stdin.read()) or 0)
    if args.action == 'serve':
        cmd = os.environ.get('SSH_ORIGINAL_COMMAND', None)
        if cmd is None:
            sys.exit(1)
        sys.exit(gd.serve(args.user, cmd) or 0)
    if args.action == 'update-hook':
        sys.exit(gd.update_hook() or 0)
    if args.action == 'git-daemon':
        sys.exit(gd.git_daemon(args.repo) or 0)
    if args.action == 'permissions-check':
        sys.exit(gd.permissions_check(args.repo, args.ref, args.old, args.new) or 0)
    assert False

if __name__ == '__main__':
    main()
