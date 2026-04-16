from keystonemiddleware.auth_token import AuthProtocol
from keystoneauth1 import session, exceptions as ks_exceptions
from keystoneclient.v3 import client as ks_client
from oslo_cache import core as cache
from oslo_cache import exception as cache_exceptions
from oslo_config import cfg
from oslo_log import log as logging

CONF = cfg.CONF
project_name = getattr(CONF, "project", None) or getattr(
    CONF, "project_name", None
)

if project_name:
    logger_name = f"{project_name}.domain_resolver_from_token"
else:
    logger_name = __name__

LOG = logging.getLogger(logger_name)


class DomainResolverFromTokenMiddleware(AuthProtocol):
    """Middleware that resolves domain_id from domain_name using Keystone.

    If a token contains a domain name but not a domain ID, this middleware
    queries Keystone to resolve the domain_id, caches the result (if cache is
    enabled), and injects HTTP_X_DOMAIN_ID into the WSGI environ.
    """

    def __init__(self, app, conf):
        super(DomainResolverFromTokenMiddleware, self).__init__(app, conf)
        LOG.info("[domain_resolver_from_token] middleware initialized"
                 " and active in pipeline")

        self._cache_region = None
        cache_section = getattr(CONF, "cache", None)
        cache_enabled = getattr(cache_section, "enabled", False)

        if cache_enabled:
            cache.configure(CONF)
            self._cache_region = cache.create_region()
            cache.configure_cache_region(CONF, self._cache_region)
            LOG.info(
                "[domain_resolver_from_token:init] Cache region initialized "
                f"(backend={CONF.cache.backend})")
        else:
            LOG.info("[domain_resolver_from_token:init] oslo_cache disabled"
                     " or [cache] section missing")

    def _get_cached_domain_id(self, domain_name):
        """Try to read domain_id from cache."""
        if not (self._cache_region and domain_name):
            return None
        try:
            return self._cache_region.get(domain_name)
        except cache_exceptions.ConfigurationError as e:
            LOG.error(f"Cache configuration invalid: {e}")
        except cache_exceptions.QueueEmpty as e:
            LOG.warning(
                f"Cache backend queue is empty for {domain_name}: {e}")
        except Exception as e:
            LOG.debug(
                f"Unexpected cache read error for {domain_name}: {e}")
        return None

    def _set_cached_domain_id(self, domain_name, domain_id):
        """Try to store domain_id in cache."""
        if not (self._cache_region and domain_name and domain_id):
            return
        ttl = CONF.get("domain_resolver_cache_ttl", 3600)
        try:
            self._cache_region.set(domain_name, domain_id, ttl=ttl)
        except cache_exceptions.ConfigurationError as e:
            LOG.error(f"Cache configuration invalid: {e}")
        except cache_exceptions.QueueEmpty as e:
            LOG.warning(f"Cache backend queue is empty on write: {e}")
        except Exception as e:
            LOG.debug(
                f"Unexpected cache write error for {domain_name}: {e}")

    def process_request(self, request):
        """Executed for each HTTP request
         before reaching the API controller."""
        result = super(
            DomainResolverFromTokenMiddleware,
            self).process_request(request)
        if result:
            return result

        token_info = request.environ.get("keystone.token_info", {}
                                         ).get("token", {})
        domain_id = None
        domain_name = None

        # Extract potential domain info from the token
        if "domain" in token_info:
            domain_id = token_info["domain"].get("id")
            domain_name = token_info["domain"].get("name")
        elif "project" in token_info and "domain" in token_info["project"]:
            domain_id = token_info["project"]["domain"].get("id")
            domain_name = token_info["project"]["domain"].get("name")
        elif "user" in token_info and "domain" in token_info["user"]:
            domain_id = token_info["user"]["domain"].get("id")
            domain_name = token_info["user"]["domain"].get("name")

        if domain_id:
            request.environ["HTTP_X_DOMAIN_ID"] = domain_id
            LOG.debug(f"Domain ID from token: {domain_id}")
            return None

        if domain_name:
            cached_id = self._get_cached_domain_id(domain_name)
            if cached_id:
                request.environ["HTTP_X_DOMAIN_ID"] = cached_id
                LOG.debug(f"Resolved {domain_name} "
                          f" {cached_id} (from cache)")
                return None

            try:
                sess = session.Session()
                ks = ks_client.Client(
                    session=sess,
                    endpoint=CONF.keystone_authtoken.auth_url)
                domains = ks.domains.list(name=domain_name)
                if not domains:
                    LOG.warning(f"Domain '{domain_name}'"
                                f" not found in Keystone")
                    return None
                if len(domains) != 1:
                    LOG.warning(
                        "Not able determine domain id by name or "
                        f"multiple domains found with name {domain_name}"
                    )
                    return None
                resolved_id = domains[0].id

                self._set_cached_domain_id(domain_name, resolved_id)
                request.environ["HTTP_X_DOMAIN_ID"] = resolved_id
                LOG.info(f"Resolved domain_name={domain_name}"
                         f" domain_id={resolved_id}")
            except ks_exceptions.HttpError as e:
                LOG.error(f"Keystone HTTP error resolving '{domain_name}': {e}")
            except ks_exceptions.ClientException as e:
                LOG.error(f"Keystone client error resolving '{domain_name}': {e}")
            except Exception as e:
                LOG.exception(f"Unexpected error resolving domain '{domain_name}': {e}")
            return None
        if domain_id:
            request.environ['HTTP_X_DOMAIN_ID'] = domain_id
            LOG.debug(f"[domain_resolver_from_token] injected"
                      f" domain_id={domain_id} into environ")
        else:
            LOG.debug("[domain_resolver_from_token] no domain_id found"
                      " in token or Keystone")
        return None

    @staticmethod
    def factory(global_conf, **local_conf):
        def _factory(app):
            return DomainResolverFromTokenMiddleware(app, local_conf)
        return _factory
