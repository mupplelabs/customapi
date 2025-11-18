from flask import request, jsonify
import requests as send_HTTP
from functools import wraps, lru_cache
from isi.papi import basepapi
from isi import config
import time

def CacheTTLHash(timeout) :
    """
    Calculates the hash value for a given timeout value using the current time.

    Parameters:
        timeout (int): The timeout value in seconds.

    Returns:
        int: The hash value calculated using the formula round(time.time() / timeout).
    """
    return round(time.time() / timeout)

class isi_auth :
    
    username    = ''
    groups      = []
    privileges  = []
    access_zone = ''
    zone_id     = 0 
    zone_path   = ''

    class config :
        token_cache_timeout         = 300   # default cache timeout for token in seconds
        token_cache_slots           = 10    # default number of available cache slots
        zoneinfo_cache_slots        = 10    # default number of available cache slots

    __token_cache_ttl_hash__        = CacheTTLHash(config.token_cache_timeout)

    def token(self) :
        return {
            'username'      : self.username,
            'groups'        : self.groups,
            'privileges'    : self.privileges,
            'access_zone'   : self.access_zone,
            'zone_id'       : self.zone_id,
            'zone_path'     : self.zone_path
            }
        
    class AuthException(Exception):
        def __init__(self, message, code, error = 'AEC_AUTH_ERROR'):
            self.code    = code
            self.error   = error
            self.message = message
            super().__init__(message)

    def __init__(self, app, logger):
        self.log = logger
        self.app = app


    def auth(self, privileges=['ISI_PRIV_LOGIN_PAPI'], role=None, username=None, zones=['all'], group=None):
        """
        Authorization decorator for Flask routes.

        This decorator checks if the user has the required privileges, zone, and group for the route to be executed.
        If the user doesn't have the required privileges, zone, and group, it returns a 403 Forbidden response.

        Parameters:
            privileges (list): The list of privileges required to execute the route. Defaults to ['ISI_PRIV_LOGIN_PAPI'].
            username (str): The username required to execute the route. Defaults to None.
            zone (str): The zone required to execute the route. Defaults to None.
            group (str): The group required to execute the route. Defaults to None.

        Returns:
            function: The decorated function.
        """
        def decorator(f):
            """
            The decorator function.

            Parameters:
                f (function): The function to be executed.

            Returns:
                function: The decorated function.
            """
            @wraps(f)
            def decorated_function(*args, **kwargs):
                """
                The decorated function.

                This function checks if the user has the required privileges, zone, and group for the route to be executed.
                If the user doesn't have the required privileges, zone, and group, it returns a 403 Forbidden response.
                Otherwise, it executes the route.

                Parameters:
                    args: The positional arguments.
                    kwargs: The keyword arguments.

                Returns:
                    Response: The response from the route if the user has the required privileges, zone, and group. Otherwise, it returns a 403 Forbidden response.
                """
                self.__init_user_auth() # Initialize user authentication information
                tmp_user        = username == self.username  if username else True              # is allowed username?
                tmp_groups      = group in self.groups       if group else True                 # is allowed group?
                tmp_zone        = self.access_zone in zones  if not 'all' in zones else True    # is allowed zone?
                tmp_privileges  = self.has_required_privileges(privileges)                      # has the privileges?
                tmp_has_role    = self.check_user_role(role, self.__token_cache_ttl_hash__) if role is not None else True      # Check if the user has the required role
                if all([tmp_user, tmp_groups, tmp_zone, tmp_privileges, tmp_has_role]): 
                    result = f( *args, **kwargs) # If yes, execute the route
                else: # If no, return a 403 Forbidden response
                    raise self.AuthException(error='AEC_FORBIDDEN', message= f"{request.method} - {request.path}: User '{self.username}' does not have required privileges to access this route in zone '{self.access_zone}'!" , code=403)
                return result # Return the response from the route
            return decorated_function
        return decorator

    def get_lnn(self) -> int:
        """
        Return the local node number LNN.

        Returns:
            int: The local node number LNN.
        """
        return config.getNode().get('lnn', 0)
    
    @lru_cache(maxsize=config.zoneinfo_cache_slots)
    def get_zone_by_ip(self, ip_address: str) -> str:
        """
        Given an IP address, return the access zone that owns it.

        Args:
            ip_address (str): The IP address to search for.

        Returns:
            str: The access zone that owns the IP address.

        Raises:
            Exception: If the API call to retrieve the network interfaces fails,
                or if the IP address is not found in any interface.
        """
        self.log.debug(f'Getting zone by IP: {ip_address}')
        # Retrieve the network interfaces from the API
        isi_network_interfaces = basepapi.get('/18/network/interfaces', args={'lnn': self.get_lnn()})
        try :
            isi_network_interfaces.raise_for_status()
        except basepapi.PapiError as e:
            self.log.debug(f'Failed to get network interfaces from API. Error(s): {e.body["errors"]}')
            raise self.AuthException(error='AEC_SYSTEM_INTERNAL_ERROR', message="Failed to get interfaces from API!", code=500)
        else :
            # Search for the interface that has the IP address
            for iface in isi_network_interfaces.body['interfaces']:
                if ip_address in iface['ip_addrs']:
                    # Find the owner of the interface that has the IP address
                    for owner in iface['owners']:
                        if ip_address in owner['ip_addrs']:
                            access_zone = owner['access_zone']
                            self.log.debug(f'Found access zone: "{access_zone}" for IP: {ip_address}')
                            return access_zone
            # If no interface is found, raise an exception
            raise self.AuthException(error='AEC_FORBIDDEN', message=f"Couldn't find zone for HOST/IP{ip_address}.", code=403)
                
    @lru_cache(maxsize=config.zoneinfo_cache_slots)
    def get_zone_from_host(self, Host_FQDN):
        """
        Given the host FQDN, return the access zone that owns it.
        The function first retrieves all network pools from the API,
        and then searches for a pool that has the same FQDN as the host.
        If a pool is found, the function returns the access zone of that pool.
        If no pool is found, the function falls back to using get_zone_by_ip to
        get the access zone from the IP address of the host.

        Args:
            Host_FQDN (str): The host FQDN to search for.

        Returns:
            str: The access zone that owns the host FQDN.

        Raises:
            Exception: If the API call to retrieve the network pools fails.
        """
        isi_network_pools = basepapi.get('/18/network/pools')
        try :
            isi_network_pools.raise_for_status()
        except basepapi.PapiError as e:
            self.log.debug(f'Failed to get network pools from API. Error Code: {e.status}. Error(s): {e.body["errors"]}')# Raise an exception if the API call fails
        else :
            try :
                access_zone = [pool['access_zone'] for pool in isi_network_pools.body['pools'] if pool['sc_dns_zone'].lower() == Host_FQDN.lower()][0]
            except IndexError :
                self.log.debug(f'Failed to resolve {Host_FQDN} as FQDN. Trying to get zone by IP address.')
                access_zone = self.get_zone_by_ip(Host_FQDN)
            else:
                self.log.debug(f'Found zone: {access_zone} for host: {Host_FQDN}')
            finally:    
                return access_zone
        
        
    @lru_cache(maxsize=config.zoneinfo_cache_slots)
    def get_zone_path(self, zone: str) -> str:
        """
        Returns the path of the zone.

        The function retrieves the path of the zone from the API,
        by making a GET request to the `/3/zone/{zone}` endpoint on the
        HOST specified in the `X-Forwarded-Host` header.

        The function returns the path of the zone as a string.

        Args:
            zone (str): The name of the zone.

        Returns:
            str: The path of the zone.

        Raises:
            AuthException: If the API call to retrieve the zone path fails.
        """
        self.log.debug(f'Getting zone path for zone: {zone}')
        zone_path = basepapi.get(f'/3/zones/{zone}')
        try:
            zone_path.raise_for_status()
        except basepapi.PapiError as e:
            self.log.debug(f'Failed to get zone path from API. Error(s): {e.body["errors"]}')
            raise self.AuthException(error='AEC_SYSTEM_INTERNAL_ERROR', message="Failed to get zone path from API!", code=500)
        else :
            zPath = zone_path.body['zones'][0]['path']
            self.log.debug(f'Got zone path: {zPath}')
            return zPath

        
    @lru_cache(maxsize=config.token_cache_slots)
    def get_isi_id(self, username: str, host: str, ttlHash = None) -> dict:
        """
        Returns the authentication ID of the user from the API.

        The function retrieves the authentication ID of the user from the API,
        by making a GET request to the `/platform/18/auth/id` endpoint on the
        HOST specified in the `X-Forwarded-Host` header.

        The function returns the authentication ID as a dictionary with the
        following keys:
            - `zid`       : The zone ID of the user.
            - `zone_id`   : The zone ID of the user.
            - `privilege` : The privileges of the user.

        If the request fails, the function raises an `AuthException` with the
        following message:
            - "Failed to get id from API."

        Returns:
            dict: The authentication ID of the user.

        Raises:
            AuthException: If the request to the API fails.
        """
        del ttlHash     # unused for lru_cache management only
        del username    # unused for lru_cache management only
        isi_auth_id_uri = 'https://' + host + ':8080/platform/18/auth/id'
        isi_auth_id = send_HTTP.get(isi_auth_id_uri, headers=request.headers, verify=False, timeout=5)
        if isi_auth_id.status_code == 200 :
            return isi_auth_id.json().get('ntoken', 
                                        { 'zid' : 0, 
                                        'zone_id' : "",
                                        'privilege' : [] 
                                        })
        else :
            raise self.AuthException(error='AEC_UNAUTHORIZED', message=f"Failed to get id for user {request.headers.get('X-Remote-User')} from API at '{host}' - reason: {isi_auth_id.reason}, status: '{isi_auth_id.status_code}'.", code=401) 

    def __init_user_auth(self):
        """
        Initializes the user authentication information.

        This function retrieves the authentication information from the request headers and sets it in the object instance's attributes. 
        If the request header contains the 'Authorization' field with the value 'Basic', it validates if the user can actually login to the HOST provided by the 'X-Forwarded-Host' header.
        The authentication information includes the user's API username (`username`), groups (`groups`), privileges (`privileges`), access zone (`access_zone`), and zone ID (`zone_id`).

        Parameters:
            self (object): The instance of the class.

        Returns:
            None
        """
        if 'Basic'.lower() in request.headers.get('Authorization', '').lower() : # in basic auth validate if the user can actually login to the HOST provided by X-Forwarded-Host
            _ =self.get_isi_id(username=request.headers.get('X-Remote-User'), host=request.headers.get('X-Forwarded-Host').split(':')[0], ttlHash=self.__token_cache_ttl_hash__)                                                 # this basically checks username and password against the API, if it fails it raises an exception
                                                                                 # Basically this is required to prevent mangling with the "Hosts" header to gain access to other access zones. 
                                                                                 # It will fail (unless a user with the exact password exists in more than one zone) 
        self.username     = request.headers.get('X-Remote-User')
        self.log.debug(f'Got username: {self.username}')
        self.access_zone  = self.get_zone_from_host(request.headers.get('X-Forwarded-Host').split(':')[0]) 
        self.log.debug(f'Got access zone: {self.access_zone}')
        self.zone_path    = self.get_zone_path(self.access_zone)
        self.log.debug(f'Got zone path: {self.zone_path}')
        self.zone_id, self.privileges, self.groups  = self.get_auth_token(self.username, self.access_zone, self.__token_cache_ttl_hash__)

    @lru_cache(maxsize=config.token_cache_slots)
    def check_user_role(self, role, ttlHASH = None):
        """
        A function to check if the user has a specific role.

        Parameters:
            self (object): The instance of the class.
            role (str): The role to check for.

        Returns:
            bool: True if the user has the role, False otherwise.
        """
        del ttlHASH
        self.log.debug(f'Checking user role: {role}')
        if role :
            authRole = basepapi.get(f'8/auth/roles/{role}/members')
            try :
                authRole.raise_for_status()
            except basepapi.PapiError as e:
                self.log.debug(f'Failed to get roles from API. Error(s): {e.body["errors"]}')
                raise self.AuthException(error='AEC_SYSTEM_INTERNAL_ERROR', message="Failed to get roles from API.", code=500)
            else :
                return self.username in authRole.body['members'] if basepapi.status == 200 else False
        return False
    @lru_cache(maxsize=config.token_cache_slots)
    def get_auth_token(self, user, zone, ttlHASH = None):
        """
        Retrieves the zid and privileges of a given user in a specified zone.

        Parameters:
            user (str): The username of the user.
            zone (str): The zone in which the user is located.

        Returns:
            tuple: A tuple containing the zid and privileges of the user.
        """
        del ttlHASH
        self.log.debug(f'Getting user token: {user}')
        tmp_token = basepapi.get(
                '/18/auth/mapping/users/lookup', args=
                {
                    'zone': zone,
                    'user': user
                })
        try: 
            tmp_token.raise_for_status()
        except basepapi.PapiError as e:  
            self.log.debug(f'Failed to get user token for user: {user} in zone: {zone}. Error(s): ' + "; ".join([error['message'] for error in e.body['errors']]))
            raise self.AuthException(error='AEC_SYSTEM_INTERNAL_ERROR', message=f'Failed to get user token for user: {user} in zone: {zone}.', code=500)
        else: 
            privileges = {}
            groups      = [group['name'] for group in tmp_token.body['mapping'][0]['groups']] 
            zid         = tmp_token.body['mapping'][0]['zid']
            for priv in [{priv['id']: priv['permission'] } for priv in tmp_token.body['mapping'][0]['privileges']] :
                privileges.update(priv)
            return zid, privileges, groups
            

    def has_required_privileges(self, required = ['ISI_PRIV_LOGIN_PAPI']): # TODO: implement privilege inheritance
        """
        Checks that the user has all the required privileges.

        Args:
            user_privileges (list): List of privileges held by the user.
            required (list): List of required privileges can bei either list of strings or dicts.
            Defaults to ['ISI_PRIV_LOGIN_PAPI'].

        Returns:
            bool: True if the user has all the required privileges, False otherwise.
        """
        if type(required) == list and len(required) > 0:
            permissions  = []
            perm_weights = {
                'w' : 4,
                'x' : 3,
                'r' : 2,
                '+' : 1,
                '-' : 0
            }
            user_privileges = self.privileges
            for perm in required :
                if type(perm) == dict :
                    for key, value in perm.items():
                        #print(f'{key} : {user_privileges.get(key)} required: {value}')
                        permissions.append(perm_weights.get(user_privileges.get(key, '-')) >= perm_weights.get(value.lower(), 0)) # how to hadle explicit deny (-)?
                        
                elif type(perm) == str :
                    #print(f'{perm} : {user_privileges.get(perm)} required: {perm}')
                    permissions.append(user_privileges.get(perm) != None)
                else :
                    raise TypeError
        elif type(required) == list and len(required) == 0 :
            permissions = [True]
        else :
            raise TypeError
        return all(permissions)