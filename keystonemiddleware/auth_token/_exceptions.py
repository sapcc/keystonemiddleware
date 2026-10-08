# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystonemiddleware import exceptions


ConfigurationError = exceptions.ConfigurationError


class InvalidToken(exceptions.KeystoneMiddlewareException):
    pass


class ServiceError(exceptions.KeystoneMiddlewareException):
    pass


class TooManyRequests(exceptions.KeystoneMiddlewareException):
    """The identity server rate-limited the token validation request.

    Raised when the identity server responds with HTTP 429 while validating
    a token. Carries the value of any ``Retry-After`` header so it can be
    propagated back to the caller.
    """

    def __init__(self, *args, **kwargs):
        self.retry_after = kwargs.pop('retry_after', 0)
        super(TooManyRequests, self).__init__(*args, **kwargs)


class RevocationListError(exceptions.KeystoneMiddlewareException):
    pass
