# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Joyent Cloud (http://www.joyentcloud.com) driver.
"""

import base64
import datetime

try:
    import simplejson as json
except:
    import json

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    pycrypto_available = True
except ImportError:
    pycrypto_available = False

from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import b

from libcloud.common.types import LibcloudError
from libcloud.compute.providers import Provider
from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.compute.types import NodeState, InvalidCredsError
from libcloud.compute.base import Node, NodeDriver, NodeImage, NodeSize
from libcloud.utils.networking import is_private_subnet

API_HOST_SUFFIX = '.api.joyentcloud.com'
API_VERSION = '~7.0'


NODE_STATE_MAP = {
    'provisioning': NodeState.PENDING,
    'running': NodeState.RUNNING,
    'stopping': NodeState.TERMINATED,
    'stopped': NodeState.TERMINATED,
    'deleted': NodeState.TERMINATED
}

VALID_REGIONS = ['us-east-1', 'us-west-1', 'us-sw-1', 'eu-ams-1']
DEFAULT_REGION = 'us-east-1'


class JoyentException(Exception):
    def __str__(self):
        return self.args[0]

    def __repr__(self):
        return "<JoyentException '%s'>" % (self.args[0])


class JoyentResponse(JsonResponse):
    """
    Joyent response class.
    """

    valid_response_codes = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                            httplib.NO_CONTENT]

    def parse_error(self):
        if self.status == httplib.UNAUTHORIZED:
            data = self.parse_body()
            raise InvalidCredsError(data['code'] + ': ' + data['message'])
        return self.body

    def success(self):
        return self.status in self.valid_response_codes


class JoyentConnection(ConnectionUserAndKey):
    """
    Joyent connection class.
    """

    responseCls = JoyentResponse

    allow_insecure = False

    def __init__(self, user_id, key, secure=True,
                 host=None, port=None, url=None, timeout=None, pkey_path=None):
        """

        :param    user_id:    Username used to login to Joyent SmartDataCenter
        :type     user_id:    ``str``

        :param    key:        Name of a public RSA key uploaded to the user account
        :type     key:        ``str``

        :param    pkey_path   Local file path to a RSA Private key for the corresponding public key
                                which will be used to sign requests
        :tpye     pkey_path   ``str``

        """
        super(JoyentConnection, self).__init__(user_id, key, secure=secure,
                                               host=host, port=port,
                                               url=url, timeout=timeout)

        if pkey_path is None:
            raise JoyentException("Joyent CloudAPI requires an SSH RSA key for signing requests")

        with open(pkey_path, "r") as key:
            self.pkey = key.read()

    def add_default_headers(self, headers):
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json; charset=UTF-8'
        headers['X-Api-Version'] = API_VERSION

        headers['Date'] = datetime.datetime.utcnow().strftime("%a, %d %h %Y %H:%M:%S GMT")
        signature = self._generate_header_signature(headers['Date'])
        headers['Authorization'] = 'Signature keyId="/%s/keys/%s",algorithm="rsa-sha256" %s' % (self.user_id, self.key, signature)
        return headers

    def _generate_header_signature(self, data_to_sign):
        rsakey = RSA.importKey(self.pkey)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        digest.update(data_to_sign)
        signature = signer.sign(digest)
        return base64.b64encode(signature)


class JoyentNodeDriver(NodeDriver):
    """
    Joyent node driver class.
    """

    type = Provider.JOYENT
    name = 'Joyent'
    website = 'http://www.joyentcloud.com'
    connectionCls = JoyentConnection
    features = {'create_node': ['generates_password']}

    def __init__(self, key, secret=None, secure=True, host=None, port=None,
                 region=DEFAULT_REGION, **kwargs):
        # Location is here for backward compatibility reasons
        if 'location' in kwargs:
            region = kwargs['location']

        if region not in VALID_REGIONS:
            msg = 'Invalid region: "%s". Valid region: %s'
            raise LibcloudError(msg % (region,
                                ', '.join(VALID_REGIONS)), driver=self)

        self.pkey_path = kwargs.get('pkey_path', None)

        super(JoyentNodeDriver, self).__init__(key=key, secret=secret,
                                               secure=secure, host=host,
                                               port=port, region=region,
                                               **kwargs)
        self.connection.host = region + API_HOST_SUFFIX

    def list_images(self):
        result = self.connection.request('/my/datasets').object

        images = []
        for value in result:
            extra = {'type': value['type'], 'os': value['os']}

            if 'urn' in value:
                extra['urn'] = value['urn']

            image = NodeImage(id=value['id'], name=value['name'],
                              driver=self.connection.driver, extra=extra)
            images.append(image)

        return images

    def list_sizes(self):
        result = self.connection.request('/my/packages').object

        sizes = []
        for value in result:
            size = NodeSize(id=value['name'], name=value['name'],
                            ram=value['memory'], disk=value['disk'],
                            bandwidth=None, price=0.0,
                            driver=self.connection.driver)
            sizes.append(size)

        return sizes

    def list_nodes(self):
        result = self.connection.request('/my/machines').object

        nodes = []
        for value in result:
            node = self._to_node(value)
            nodes.append(node)

        return nodes

    def reboot_node(self, node):
        data = json.dumps({'action': 'reboot'})
        result = self.connection.request('/my/machines/%s' % (node.id),
                                         data=data, method='POST')
        return result.status == httplib.ACCEPTED

    def destroy_node(self, node):
        result = self.connection.request('/my/machines/%s' % (node.id),
                                         method='DELETE')
        return result.status == httplib.NO_CONTENT

    def create_node(self, **kwargs):
        name = kwargs['name']
        size = kwargs['size']
        image = kwargs['image']

        data = json.dumps({'name': name, 'package': size.id,
                           'dataset': image.id})
        result = self.connection.request('/my/machines', data=data,
                                         method='POST')
        return self._to_node(result.object)

    def ex_stop_node(self, node):
        """
        Stop node

        :param  node: The node to be stopped
        :type   node: :class:`Node`

        :rtype: ``bool``
        """
        data = json.dumps({'action': 'stop'})
        result = self.connection.request('/my/machines/%s' % (node.id),
                                         data=data, method='POST')
        return result.status == httplib.ACCEPTED

    def ex_start_node(self, node):
        """
        Start node

        :param  node: The node to be stopped
        :type   node: :class:`Node`

        :rtype: ``bool``
        """
        data = json.dumps({'action': 'start'})
        result = self.connection.request('/my/machines/%s' % (node.id),
                                         data=data, method='POST')
        return result.status == httplib.ACCEPTED

    def _to_node(self, data):
        state = NODE_STATE_MAP[data['state']]
        public_ips = []
        private_ips = []
        extra = {}

        for ip in data['ips']:
            if is_private_subnet(ip):
                private_ips.append(ip)
            else:
                public_ips.append(ip)

        if 'credentials' in data['metadata']:
            extra['password'] = data['metadata']['credentials']['root']

        node = Node(id=data['id'], name=data['name'], state=state,
                    public_ips=public_ips, private_ips=private_ips,
                    driver=self.connection.driver, extra=extra)
        return node

    def _ex_connection_class_kwargs(self):
        """
        Return extra connection keyword arguments which are passed to the
        Connection class constructor.
        """
        kwargs = {}

        if self.pkey_path is not None:
            kwargs['pkey_path'] = self.pkey_path

        return kwargs
