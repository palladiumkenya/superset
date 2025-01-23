from flask import redirect, request
from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_babel import _
from superset.exceptions import SupersetSecurityException
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView, expose
from flask_login import login_user
from flask_appbuilder.views import expose
from superset_config import CustomUser
import logging

class AuthOIDCView(AuthOIDView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            info = oidc.user_getinfo(['preferred_username','email', 'name', 'OrganizationId','OrganizationName','FullName','UserType','UserConfirmed','County'])
            user_confirmed = info.get('UserConfirmed')
            logging.info('Attempint login for email: '+ info.get('email'))
            if user_confirmed == '2':
                logging.info('User ' + info.get('email') + ' has been disabled')
                raise SupersetSecurityException(
                    SupersetError(
                        error_type=SupersetErrorType.USER_ACTIVITY_SECURITY_ACCESS_ERROR,
                        level=ErrorLevel.ERROR,
                        message=_("User account is disabled"),
                    )
                )
            user = sm.auth_user_oid(info.get('email'))
            logging.info('Fetched user: ' + info.get('email')) 
            if user is None:
                full_name_array = None
                if not info.get('name') is None and info.get('name') != '':
                    full_name_array = info.get('name').split()
                elif not info.get('FullName') is None and info.get('FullName') != '':
                    full_name_array = info.get('FullName').split()
                else:
                    raise SupersetSecurityException(
                    SupersetError(
                        error_type=SupersetErrorType.USER_ACTIVITY_SECURITY_ACCESS_ERROR,
                        level=ErrorLevel.ERROR,
                        message=_("User account does not have required field (name)"),
                    )
                )

                given_name = full_name_array[0]
                if (len(full_name_array) > 1):
                    family_name = full_name_array[1]
                logging.info('Full name is: '+ given_name+' '+ family_name)
                existing_role = sm.find_role(info.get('OrganizationName'))
                logging.info(existing_role)
                user = sm.add_user(info.get('preferred_username'),
                                   given_name,
                                   family_name,
                                   info.get('email'),
                                   existing_role,
                                   info.get('OrganizationName'),
                                   info.get('UserType'))
            login_user(user, remember = False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid
        oidc.logout()
        super(AuthOIDCView, self).logout()
        return redirect(oidc.client_secrets.get('end_session_uri'))

class OIDCSecurityManager(SupersetSecurityManager):
    authoidview = AuthOIDCView
    user_model = CustomUser
    def add_user(
        self, 
        username, 
        first_name, 
        last_name, 
        email, 
        role, 
        organization_name,
        user_type
    ):
        logging.info('inside custom add user method')
        user = super().add_user(username, first_name, last_name, email, role)
        user.organization_name = organization_name
        user.user_type = user_type
        self.get_session.merge(user)
        self.get_session.commit()
        return user
    
    
    def __init__(self, appbuilder):
         super(OIDCSecurityManager, self).__init__(appbuilder)
         if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
         self.authoidview = AuthOIDCView
