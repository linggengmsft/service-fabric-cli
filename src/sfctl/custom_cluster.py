# -----------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

"""Cluster level Service Fabric commands"""

import adal
from knack.util import CLIError

def select_arg_verify(endpoint, cert, key, pem, ca, aad, no_verify):
    """Verify arguments for select command"""

    if not (endpoint.lower().startswith('http')
            or endpoint.lower().startswith('https')):
        raise CLIError('Endpoint must be HTTP or HTTPS')

    usage = ('Valid syntax : --endpoint [ [ --key --cert | --pem | --aad] '
             '[ --ca | --no-verify ] ]')

    if ca and not (pem or all([key, cert])):
        raise CLIError(usage)

    if no_verify and not (pem or all([key, cert]) or aad):
        raise CLIError(usage)

    if no_verify and ca:
        raise CLIError(usage)

    if any([cert, key]) and not all([cert, key]):
        raise CLIError(usage)

    if aad and any([pem, cert, key]):
        raise CLIError(usage)

    if pem and any([cert, key]):
        raise CLIError(usage)

def select(endpoint, cert=None, key=None, pem=None, ca=None,
           aad=False, no_verify=False):
    #pylint: disable-msg=R0914
    """
    Connects to a Service Fabric cluster endpoint.
    If connecting to secure cluster specify a cert (.crt) and key file (.key)
    or a single file with both (.pem). Do not specify both. Optionally, if
    connecting to a secure cluster, specify also a path to a CA bundle file
    or directory of trusted CA certs.
    :param str endpoint: Cluster endpoint URL, including port and HTTP or HTTPS
    prefix
    :param str cert: Path to a client certificate file
    :param str key: Path to client certificate key file
    :param str pem: Path to client certificate, as a .pem file
    :param str ca: Path to CA certs directory to treat as valid or CA bundle
    file
    :param bool aad: Use Azure Active Directory for authentication
    :param bool no_verify: Disable verification for certificates when using
    HTTPS, note: this is an insecure option and should not be used for
    production environments
    """
    from sfctl.config import (set_ca_cert, set_auth,
                              set_cluster_endpoint, client_endpoint,
                              set_no_verify, no_verify_setting)
    from msrest import ServiceClient, Configuration
    from sfctl.auth import ClientCertAuthentication, AdalAuthentication

    select_arg_verify(endpoint, cert, key, pem, ca, aad, no_verify)

    token = None
    if aad:

        token, new_cache = get_aad_token(endpoint, no_verify)
        #print(new_cache)
        rest_client = ServiceClient(
            AdalAuthentication(token, new_cache, no_verify),
            Configuration(endpoint)
        )

        # Make sure basic GET request succeeds
        rest_client.send(rest_client.get('/')).raise_for_status()
    else:
        client_cert = None
        if pem:
            client_cert = pem
        elif cert:
            client_cert = (cert, key)

        rest_client = ServiceClient(
            ClientCertAuthentication(client_cert, ca, no_verify),
            Configuration(endpoint)
        )

        # Make sure basic GET request succeeds
        rest_client.send(rest_client.get('/')).raise_for_status()

    set_cluster_endpoint(endpoint)
    set_no_verify(no_verify)
    set_ca_cert(ca)
    set_auth(pem, cert, key, token['accessToken'])

def get_aad_token(endpoint, no_verify):
    """Get AAD token"""
    from azure.servicefabric.service_fabric_client_ap_is import (
        ServiceFabricClientAPIs
    )
    from sfctl.auth import ClientCertAuthentication
    from sfctl.config import (aad_bearer, client_endpoint, set_aad_metadata,
                              set_config_value, no_verify_setting)
    from datetime import datetime
    from datetime import timedelta

    auth = ClientCertAuthentication(None, None, no_verify)

    client = ServiceFabricClientAPIs(auth, base_url=endpoint)
    aad_metadata = client.get_aad_metadata()

    if aad_metadata.type != "aad":
        raise CLIError("Not AAD cluster")

    aad_resource = aad_metadata.metadata

    tenant_id = aad_resource.tenant
    authority_uri = aad_resource.login + '/' + tenant_id
    context = adal.AuthenticationContext(authority_uri,
                                         api_version=None)
    cluster_id = aad_resource.cluster
    client_id = aad_resource.client

    set_aad_metadata(authority_uri, cluster_id, client_id)

    code = context.acquire_user_code(cluster_id, client_id)
    print(code['message'])
    token = context.acquire_token_with_device_code(
        cluster_id, code, client_id)
    print("Succeed! Token expires at: " +
          (str)(datetime.now() + timedelta(0, token['expiresIn'])))
    return token, adal.TokenCache()
