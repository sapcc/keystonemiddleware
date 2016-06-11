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

from oslo_config import cfg
import six

from keystonemiddleware import exceptions
from keystonemiddleware.i18n import _

CONF = cfg.CONF
_NOT_SET = object()


def _conf_values_type_convert(group_name, all_options, conf):
    """Convert conf values into correct type."""
    if not conf:
        return {}

    opts = {}
    opt_types = {}

    for group, options in all_options:
        # only accept paste overrides for the primary group
        if group != group_name:
            continue

        for o in options:
            type_dest = (getattr(o, 'type', str), o.dest)
            opt_types[o.dest] = type_dest
            # Also add the deprecated name with the same type and dest.
            for d_o in o.deprecated_opts:
                opt_types[d_o.name] = type_dest

        break

    for k, v in six.iteritems(conf):
        dest = k
        try:
            if v is not None:
                type_, dest = opt_types[k]
                v = type_(v)
        except KeyError:  # nosec
            # This option is not known to auth_token. v is not converted.
            # FIXME(jamielennox): This should probably log a warning.
            pass
        except ValueError as e:
            raise exceptions.ConfigurationError(
                _('Unable to convert the value of %(key)s option into correct '
                  'type: %(ex)s') % {'key': k, 'ex': e})
        opts[dest] = v

    return opts


class Config(object):

    def __init__(self, group_name, all_options, conf):
        # NOTE(wanghong): If options are set in paste file, all the option
        # values passed into conf are string type. So, we should convert the
        # conf value into correct type.
        self.paste_overrides = _conf_values_type_convert(group_name,
                                                         all_options,
                                                         conf)

        # NOTE(sileht, cdent): If we don't want to use oslo.config global
        # object there are two options: set "oslo_config_project" in
        # paste.ini and the middleware will load the configuration with a
        # local oslo.config object or the caller which instantiates
        # AuthProtocol can pass in an existing oslo.config as the
        # value of the "oslo_config_config" key in conf. If both are
        # set "olso_config_config" is used.
        local_oslo_config = None

        try:
            local_oslo_config = conf['oslo_config_config']
        except KeyError:
            if 'oslo_config_project' in conf:
                config_files = filter(None, [conf.get('oslo_config_file')])
                local_oslo_config = cfg.ConfigOpts()
                local_oslo_config([],
                                  project=conf['oslo_config_project'],
                                  default_config_files=config_files,
                                  validate_default_values=True)

        if local_oslo_config:
            for group, opts in all_options:
                local_oslo_config.register_opts(opts, group=group)

        self.oslo_conf_obj = local_oslo_config or cfg.CONF
        self.group_name = group_name

    def get(self, name, group=_NOT_SET):
        # try config from paste-deploy first
        try:
            return self.paste_overrides[name]
        except KeyError:
            if group is _NOT_SET:
                group = self.group_name

            return self.oslo_conf_obj[group][name]

    @property
    def project(self):
        """Determine a project name from all available config sources.

        The sources are checked in the following order:

          1. The paste-deploy config for auth_token middleware
          2. The keystone_authtoken or base group in the project's config
          3. The oslo.config CONF.project property

        """
        try:
            return self.get('project', group=self.group_name)
        except cfg.NoSuchOptError:
            try:
                # CONF.project will exist only if the service uses
                # oslo.config. It will only be set when the project
                # calls CONF(...) and when not set oslo.config oddly
                # raises a NoSuchOptError exception.
                return self.oslo_conf_obj.project
            except cfg.NoSuchOptError:
                return None