import ldap

from django_auth_ldap.config import ActiveDirectoryGroupType

from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django_auth_ldap.config import LDAPSearch


class GroupLDAPBackend(LDAPBackend):
    default_settings = {
        # Our new settings
        # Lets call the RegEx GROUP_REGEX for simplicity
        "GROUP_REGEX": "ou=SOMEOU,ou=SOMEOU,dc=MyCompany,dc=local",
        "GROUP_SEARCH": LDAPSearch(
            "DC=MyCompany, DC=local",
            ldap.SCOPE_SUBTREE,
            "(cn=*)"
        ),
        "GROUP_TYPE": ActiveDirectoryGroupType(name_attr="ou"),  # GroupOfNamesType(),

        # All those settings are overwriting base class values
        "SERVER_URI": "ldaps://xxxxxxx:",
        "CACHE_TIMEOUT": 3600,

        # Those settings should probably be overwritten by the settings.py
        "BIND_DN": "CN=service.account,OU=Service Accounts,OU=SOMEOU,DC=MyCompany,DC=local",
        "BIND_PASSWORD": "somepassword",
        "USER_SEARCH": LDAPSearch(
            "DC=MyCompany,DC=local", ldap.SCOPE_SUBTREE, "(sAMAccountName=%(user)s)"),
    }
    ldap.set_option(ldap.OPT_REFERRALS, 0)

    def authenticate_ldap_user(self, ldap_user: _LDAPUser, password: str):
        # This is the default implemented authentication
        user = ldap_user.authenticate(password)
        # print('mah group dns:')
        # print(user.ldap_user.group_names)

        # If the authentication was denied, we have to return None
        if not user:
            return None
        ldap_groups = ldap_user.group_names

        print('ldap groups are: ')
        print(name for name in ldap_user.group_names)

        print(ldap_user.dn)
        #    self.create_groups_and_assign_user_to_it(user, ldap_groups)
        #    print('authenticated: ' + user.is_authenticated)

        print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
        for key in user.ldap_user.attrs:
            print(f' user attribute {key} is {user.ldap_user.attrs[key]}')

        print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
        return user
