import logging
import os
import signal
import io
import docker
import docker.utils.socket as docker_socket
import six
import struct
import tarfile

from pwnlib import term
from pwnlib.context import context
from pwnlib.log import Logger
from pwnlib.timeout import Timeout
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout
from pwnlib.tubes.tube import tube
from pwnlib.util.misc import which

from pprint import pprint

class dockerized_channel(tube):
    def __init__(self, parent = None, process = None, tty = False, wd = None, env = None, privileged = False, *args, **kwargs):
        super(dockerized_channel, self).__init__(*args, **kwargs)

        self.parent = parent

        self.returncode = None
        self.tty  = tty
        self.env  = env
        self.process = process
        self.wd  = wd or '.'
        self.privileged = privileged

        self.exec_id = None
        self._buf = six.binary_type()

        if isinstance(wd, six.text_type):
            wd = wd.encode('utf-8')

        env = env or {}
        msg = 'Opening new channel: %r' % (process or 'shell')

        if process and self.isEnabledFor(logging.DEBUG):
            msg = 'Opening new channel: %r' % ((process,) or 'shell')

        with self.waitfor(msg) as h:
            self.exec_id = parent.client.api.exec_create(self.parent.container.id, process, stdin=True, stdout=True, stderr=True, tty=self.tty, privileged=self.privileged)['Id']
            self.sock = parent.client.api.exec_start(self.exec_id, tty=self.tty, socket=True)

            if self.tty:
                def resizer():
                    try:
                        parent.client.api.exec_resize(self.exec_id, term.width, term.height)
                    except Exception:
                        pass
                
                self.resizer = resizer
                term.term.on_winch.append(self.resizer)
            else:
                self.resizer = None

            self.settimeout(self.timeout)

            h.success()

    def kill(self):
        self.close()
    
    def wait(self, timeout=tube.default):
        # TODO: deal with timeouts
        return self.poll(block=True)

    def _internal_recv(self, n):
        if len(self._buf) == 0:
            (stream, size) = docker_socket.next_frame_header(self.sock)
            while size > 0:
                result = docker_socket.read(self.sock, size)
                if result is None:
                    continue
                data_length = len(result)
                if data_length == 0:
                    raise EOFError
                size -= data_length
                self._buf += result

        end = min(len(self._buf), n)
        ret = self._buf[:end]
        self._buf = self._buf[end:]
        return ret
        
    def recv_raw(self, numb):
        data = ''
        try:
            if self.tty:
                data = docker_socket.read(self.sock, numb)
            else:
                data = self._internal_recv(numb)
        except Exception as e:
            raise EOFError
        return data

    def send_raw(self, data):
        try:
            # python3 hacky way
            # https://github.com/docker/docker-py/issues/983
            # https://github.com/docker/docker-py/issues/2255
            self.sock._sock.send(data)
        except Exception as e:
            raise EOFError

    def _close_msg(self):
        self.info('Closed docker channel with %s' % self.host)

class dockerized_process(dockerized_channel):
    _hostpid = 0
    _pid = 0
    _cwd = None

    def __init__(self, *args, **kwargs):
        super(dockerized_process, self).__init__(*args, **kwargs)

    @property
    def hostpid(self):
        while self._hostpid == 0:
            # Wait until proper info is loaded
            self._hostpid = self.parent.client.api.exec_inspect(self.exec_id)['Pid']
        return self._hostpid

    @property
    def pid(self):
        if self._pid == 0:
            with open(f'/proc/{self.hostpid}/status', 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith('NSpid:'):
                        self._pid = int(line[len('NSpid:'):].strip().split()[1])
                        break
                else:
                    raise Exception
                # Cannot get container pid, some features will not work. 
        return self._pid

    @property
    def cwd(self):
        try:
            self._cwd = os.readlink(f'/proc/{self.hostpid}/cwd')
        except Exception as e:
            # Fallback to container
            self._cwd = self.parent.readlink(f'/proc/{self.pid}/cwd').rstrip()

        return self._cwd

    '''
    def libs(self):
        try:
            maps_raw = open(f'/proc/{self.hostpid}/maps').read()
        except IOError:
            maps_raw = self.parent.cat(f'/proc/{self.pid}/maps')
        
        maps = {}
        for line in maps_raw.splitlines():
            if '/' not in line: continue
            path = line[line.index('/'):]
            path = os.path.realpath(path)
            if path not in maps:
                maps[path]=0

        for lib in maps:
            path = os.path.realpath(lib)
            for line in maps_raw.splitlines():
                if line.endswith(path):
                    address = line.split('-')[0]
                    maps[lib] = int(address, 16)
                    break

        return maps
    '''

    def close(self):
        # Try to send signal from host
        try:
            os.kill(self.hostpid, signal.SIGKILL)
        except ProcessLookupError as e:
            if e.errno != 3:
                raise e


    def poll(self, block=False):
        if self.returncode is None:
            if block:
                while True:
                    info = self.parent.client.api.exec_inspect(self.exec_id)
                    if info['Running'] == False:
                        self.returncode = info['ExitCode']
                        break
            else:
                info = self.parent.client.api.exec_inspect(self.exec_id)
                self.returncode = info['ExitCode']
        
        return self.returncode


class dockerized(Timeout, Logger):
    r"""
    Creates a new docker image and runs it. 

    Arguments:
        argv(list):
            The command to run in the container. Use image default if not specified. 
        context(str):
            Working directory when building docker image.  Uses the current working directory by default.
        dockerfile(str):
            Content of Dockerfile when new docker image will be created.

            If defined, Dockerfile existing in context will be ignored. 
        image(str):
            Docker image tag to use.
            If arg `'dockerfile'` is not specified, and Dockerfile do not exist in context, 
            no new image will be created and will run existing image. 
            
            If not defined, the default value will be :const:`'pwntools_image'`
        container_name(str):
            Docker container name to use.

            If not defined, the default value will be :const:`'pwntools_container'`
    """
    def __init__(self, argv = None,
                 context = None,
                 dockerfile = None,
                 image = None,
                 container_name = 'pwntools_container',
                 volumes = None,
                 user = None,
                 working_dir = '/root/',
                 *args,
                 **kwargs
                 ):
        super(dockerized, self).__init__(*args,**kwargs)

        Logger.__init__(self)

        self.argv = argv
        self.context = os.path.realpath(context or os.path.curdir)
        self.client = docker.from_env()
        self.image = image or 'pwntools_image'
        self.dockerfile = dockerfile or self.scripts.DEFAULT
        self.container_name = container_name
        self.volumes = volumes or {self.context: {'bind': '/root/', 'mode': 'rw'}}
        self.user = user or os.getuid()
        self.wd = working_dir

        if dockerfile is not None:
            self._mode = 'new_dockerfile'
        elif os.path.exists(os.path.join(self.context, 'Dockerfile')):
            self._mode = 'new_image'
        else:
            self._mode = 'run_image'
        
        if self._mode == 'new_dockerfile':
            with open(os.path.join(self.context, 'Dockerfile'), 'w') as f:
                f.write(self.dockerfile)

        self.docker_client = docker.from_env()
        
        if self._mode == 'new_dockerfile' or self._mode == 'new_image':
            msg = "Building image %r" % (self.image)
            with self.waitfor(msg) as h:
                try:
                    self.docker_client.images.build(path=self.context, tag=self.image)
                    # Double check image
                    self.docker_client.images.get(self.image)
                except Exception as e:
                    self.error("Failed to build image %r" % (self.image))
                    raise e
                h.success()
        
        try:
            container = self.docker_client.containers.get(self.container_name)
            if container.attrs['Config']['Image'] != self.image:
                self.warn(f"Removing container with name {self.container_name} and image {container.attrs['Config']['Image']}")
            container.remove(force=True)
        except docker.errors.NotFound:
            pass

        msg = "Running new container %r from image %r" % (self.container_name, self.image)
        with self.waitfor(msg) as h:
            try:
                self.container = self.docker_client.containers.run(self.image, argv, stdin_open=True, stderr=True, detach=True, tty=False, name=self.container_name, volumes=self.volumes, user=self.user, working_dir=self.wd, privileged=True)
            except Exception as e:
                self.error("Failed to run container %r" % (self.container_name))
                raise e
            h.success()
            # Should reload to get IP address
        
        self.container.reload()
        self.container_host = self.container.attrs['NetworkSettings']['IPAddress']
        self.sock = self.container.attach_socket(params={'stdin': 1, 'stdout': 1, 'stderr': 1, 'stream': 1, 'logs': 1})

    def __enter__(self, *a):
        return self

    def __exit__(self, *a, **kw):
        # To be implemented
        self.close()

    def close(self):
        if self.container is None:
            return
        
        try:
            self.container.kill()
            # TODO: make auto rm check
            # self.container.remove()
            self.info("Killed container %r" % self.container_name)
        except:
            self.warn("Failed when killing container %r" % self.container_name)

    def shell(self, shell = None, tty = True, timeout = Timeout.default):
        if shell is None:
            shell = '/bin/sh'
        
        return self.run(shell, tty, timeout = timeout)

    
    def system(self, process, tty = True, wd = None, env = None, privileged = False, timeout = None):
        if wd is None:
            wd = self.wd

        if timeout is None:
            timeout = self.timeout
        
        return dockerized_process(self, process, tty, wd, env, privileged, timeout = timeout, level = self.level)

    run = system

    def _download_raw(self, remote, local):
        stream, stat = self.container.get_archive(remote)
        file_compressed = io.BytesIO()
        for i in stream:
            file_compressed.write(i)
        file_compressed.seek(0)
        tar = tarfile.open(mode='r', fileobj=file_compressed)
        file = tar.extractfile(os.path.basename(remote))
        
        with open(local, 'wb') as f:
            f.write(file.read())

    def __getitem__(self, attr):
        return self.__getattr__(attr)()

    def __call__(self, attr):
        return self.__getattr__(attr)()

    def __getattr__(self, attr):
        bad_attrs = [
            'trait_names',          # ipython tab-complete
        ]

        if attr in self.__dict__ \
        or attr in bad_attrs \
        or attr.startswith('_'):
            raise AttributeError

        def runner(*args):
            if len(args) == 1 and isinstance(args[0], (list, tuple)):
                command = [attr] + args[0]
            else:
                command = ' '.join((attr,) + args)

            return self.run(command, tty=False).recvall().strip()
        return runner

    def connected(self):
        self.container.reload()
        return self.container.attrs['State']['Running']
    
    @property
    def host(self):
        self.container.reload()
        return self.container.attrs['NetworkSettings']['IPAddress']

    class scripts(object):
        DEFAULT = '''FROM ubuntu:20.04
RUN apt-get update && apt-get install gdbserver && rm -rf /var/lib/apt/lists/*
'''
        @staticmethod
        def ubuntu(version, gdbserver):
            dockerfile = f'''FROM ubuntu:{version}
'''
            if gdbserver:
                if version == '19.04':
                    pass
                else:
                    dockerfile += '''RUN apt-get update && apt-get install gdbserver && rm -rf /var/lib/apt/lists/*
'''
            return dockerfile

