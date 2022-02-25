# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

import aiohttp


class Authentication(abc.ABC):  # type: ignore
    @abc.abstractmethod
    def set_http_session(self, http_session):
        pass

    @abc.abstractmethod
    def setup(self):
        pass

    def get_exceptions(self):
        return tuple()


class BasicAuthentication(Authentication):
    def __init__(self, username, password):
        self._username = username
        self._password = password

    def set_http_session(self, http_session):
        http_session._default_auth = aiohttp.BasicAuth(self._username, self._password)
        return http_session

    def setup(self, trino_client):
        self.set_http_session(trino_client.http_session)

    def get_exceptions(self):
        return ()


class JWTAuthentication(Authentication):

    def __init__(self, token):
        self.token = token

    def set_http_session(self, http_session):
        old_headers = http_session.headers

        if not old_headers:
            old_headers = {}

        old_headers["Authorization"] = "Bearer {self.token}"

        http_session.headers = old_headers

    def get_exceptions(self):
        return ()

    def __eq__(self, other):
        if not isinstance(other, JWTAuthentication):
            return False
        return self.token == other.token
