import os
import signal
import io
import docker
import docker.utils.socket as docker_socket
import six
import struct

from pwnlib.context import context
from pwnlib.log import Logger
from pwnlib.timeout import Timeout
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout
from pwnlib.tubes.tube import tube
from pwnlib.util.misc import which

from pprint import pprint
       
class dockerized_channel(tube):
    def __init__(self, sock = None, tty = False, *args, **kwargs):
        super(dockerized_channel, self).__init__(*args, **kwargs)

        self.sock = sock
        self._buf = six.binary_type()
        self._tty = tty

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
            data = self._internal_recv(numb)
        except Exception as e:
            print(e)
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

class dockerized_process(dockerized_channel):
    def __init__(self, client, exec_id, *args, **kwargs):
        super(dockerized_process, self).__init__(*args, **kwargs)
        self.client = client
        self.exec_id = exec_id
        self._hostpid = 0
        self._pid = 0
    
    @property
    def hostpid(self):
        while self._hostpid == 0:
            # Wait until proper info is loaded
            self._hostpid = self.client.api.exec_inspect(self.exec_id)['Pid']
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
        return self._pid

    def close(self):
        # Try to send signal from host
        os.kill(self.hostpid, signal.SIGKILL)


class dockerized(dockerized_channel):
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
                 *args,
                 **kwargs
                 ):
        super(dockerized, self).__init__(*args,**kwargs)

        self.argv = argv
        self.context = os.path.realpath(context or os.path.curdir)
        self.client = docker.from_env()
        self.image = image or 'pwntools_image'
        self.dockerfile = dockerfile or self.scripts.DEFAULT
        self.container_name = container_name
        self.volumes = volumes or {self.context: {'bind': '/root/', 'mode': 'rw'}}

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
                self.container = self.docker_client.containers.run(self.image, argv, stdin_open=True, stderr=True, detach=True, tty=False, name=self.container_name, volumes=self.volumes, working_dir='/root/')
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
            self.container.remove()
            self.info("Killed container %r" % self.container_name)
        except:
            self.warn("Failed when killing container %r" % self.container_name)

    def process(self, argv = None):
        # Permit using context.binary
        if argv is None:
            if context.binary:
                argv = [context.binary.path]
            else:
                raise TypeError('Must provide argv or set context.binary')
        
        message = "Starting process"
        with self.progress(message) as h:
            try:
                exec_id = self.docker_client.api.exec_create(self.container.id, argv, stdin=True, stdout=True, stderr=True, tty=False)['Id']
                sock = self.docker_client.api.exec_start(exec_id, tty=False, socket=True)
                process = dockerized_process(self.docker_client, exec_id, sock, False)
                h.success('pid %d (hostpid %d)' % (process.pid, process.hostpid))
            except Exception as e:
                print(e)
        return process

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

