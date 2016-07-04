#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# +------------------------------------------------------------------+
# |             ____ _               _        __  __ _  __           |
# |            / ___| |__   ___  ___| | __   |  \/  | |/ /           |
# |           | |   | '_ \ / _ \/ __| |/ /   | |\/| | ' /            |
# |           | |___| | | |  __/ (__|   <    | |  | | . \            |
# |            \____|_| |_|\___|\___|_|\_\___|_|  |_|_|\_\           |
# |                                                                  |
# | Copyright Mathias Kettner 2014             mk@mathias-kettner.de |
# +------------------------------------------------------------------+
#
# This file is part of Check_MK.
# The official homepage is at http://mathias-kettner.de/check_mk.
#
# check_mk is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  check_mk is  distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.

import defaults, config, userdb
from lib import *
from mod_python import apache
import os, time
import traceback

try:
    from hashlib import md5
except ImportError:
    from md5 import md5 # deprecated with python 2.5


def auth_cookie_name():
    return 'auth%s' % site_cookie_suffix()


def site_cookie_suffix():
    url_prefix = defaults.url_prefix
    # Strip of eventual present "http://<host>". DIRTY!
    if url_prefix.startswith('http:'):
        url_prefix = url_prefix[url_prefix[7:].find('/') + 7:]

    return os.path.dirname(url_prefix).replace('/', '_')

# Reads the auth secret from a file. Creates the files if it does
# not exist. Having access to the secret means that one can issue valid
# cookies for the cookie auth.
def load_secret():
    secret_path = '%s/auth.secret' % os.path.dirname(defaults.htpasswd_file)
    secret = ''
    if os.path.exists(secret_path):
        secret = file(secret_path).read().strip()

    # Create new secret when this installation has no secret
    #
    # In past versions we used another bad approach to generate a secret. This
    # checks for such secrets and creates a new one. This will invalidate all
    # current auth cookies which means that all logged in users will need to
    # renew their login after update.
    if secret == '' or len(secret) == 32:
        secret = get_random_string(256)
        file(secret_path, 'w').write(secret)

    return secret


# Load the password serial of the user. This serial identifies the current config
# state of the user account. If either the password is changed or the account gets
# locked the serial is increased and all cookies get invalidated.
# Better use the value from the "serials.mk" file, instead of loading the whole
# user database via load_users() for performance reasons.
def load_serial(username):
    return userdb.load_custom_attr(username, 'serial', saveint, 0)


def generate_auth_hash(username, now):
    return generate_hash(username, username + str(now))


# Generates a hash to be added into the cookie value
def generate_hash(username, value):
    secret = load_secret()
    serial = load_serial(username)
    return md5(value + str(serial) + secret).hexdigest()

def del_auth_cookie():
    name = auth_cookie_name()
    if html.has_cookie(name):
        html.del_cookie(name)

def auth_cookie_value(username):
    now = str(time.time())
    return ":".join([ username, now, generate_auth_hash(username, now) ])


def invalidate_auth_session():
    if config.single_user_session != None:
        userdb.invalidate_session(config.user_id)

    del_auth_cookie()


def renew_auth_session(username):
    if config.single_user_session != None:
        userdb.refresh_session(username)

    set_auth_cookie(username)


def create_auth_session(username):
    if config.single_user_session != None:
        session_id = userdb.initialize_session(username)
        set_session_cookie(username, session_id)
    set_auth_cookie(username)


def set_auth_cookie(username):
    html.set_cookie(auth_cookie_name(), auth_cookie_value(username))


def set_session_cookie(username, session_id):
    html.set_cookie(session_cookie_name(), session_cookie_value(username, session_id))


def session_cookie_name():
    return 'session%s' % site_cookie_suffix()


def session_cookie_value(username, session_id):
    value = username + ":" + session_id
    return value + ":" + generate_hash(username, value)


def get_session_id_from_cookie(username):
    raw_value = html.cookie(session_cookie_name(), "::")
    cookie_username, session_id, cookie_hash = raw_value.split(':', 2)

    if cookie_username != username \
       or cookie_hash != generate_hash(username, username + ":" + session_id):
        #logger(LOG_ERR, "Invalid session: %s, Cookie: %r" % (username, raw_value))
        return ""

    return session_id


def renew_cookie(cookie_name, username):
    # Do not renew if:
    # a) The _ajaxid var is set
    # b) A logout is requested
    if (html.myfile != 'logout' and not html.has_var('_ajaxid')) \
       and cookie_name == auth_cookie_name():
        set_auth_cookie(username)


def parse_auth_cookie(cookie_name):
    raw_value = html.cookie(cookie_name, "::")
    username, issue_time, cookie_hash = raw_value.split(':', 2)
    return username, float(issue_time), cookie_hash

def check_auth_cookie(cookie_name):
    username, issue_time, cookie_hash = parse_auth_cookie(cookie_name)

    # FIXME: Ablauf-Zeit des Cookies testen
    #max_cookie_age = 10
    #if float(issue_time) < time.time() - max_cookie_age:
    #    del_auth_cookie()
    #    return ''

    if not userdb.user_exists(username):
        raise MKAuthException(_('Username is unknown'))

    # Validate the hash
    if cookie_hash != generate_auth_hash(username, issue_time):
        raise MKAuthException(_('Invalid credentials'))

    # Check whether or not there is an idle timeout configured, delete cookie and
    # require the user to renew the log when the timeout exceeded.
    if userdb.login_timed_out(username, float(issue_time)):
        del_auth_cookie()
        return

    # Check whether or not a single user session is allowed at a time and the user
    # is doing this request with the currently active session.
    if config.single_user_session != None:
        session_id = get_session_id_from_cookie(username)
        if not userdb.is_valid_user_session(username, session_id):
            del_auth_cookie()
            return

    # Once reached this the cookie is a good one. Renew it!
    renew_cookie(cookie_name, username)

    if html.myfile != 'user_change_pw':
        result = userdb.need_to_change_pw(username)
        if result:
            html.http_redirect('user_change_pw.py?_origtarget=%s&reason=%s' % (html.urlencode(html.makeuri([])), result))

    # Return the authenticated username
    return username

def check_auth_automation():
    secret = html.var("_secret").strip()
    user = html.var("_username").strip()
    html.del_var('_username')
    html.del_var('_secret')
    if secret and user and "/" not in user:
        path = defaults.var_dir + "/web/" + user + "/automation.secret"
        if os.path.isfile(path) and file(path).read().strip() == secret:
            # Auth with automation secret succeeded - mark transid as unneeded in this case
            html.set_ignore_transids()
            return user
    raise MKAuthException(_("Invalid automation secret for user %s") % html.attrencode(user))

def check_auth():
    if html.var("_secret"):
        return check_auth_automation()

    # When http header auth is enabled, try to read the username from the var
    # and when there is some available, set the auth cookie (for other addons) and proceed.
    if config.auth_by_http_header:
        username = html.req.headers_in.get(config.auth_by_http_header, None)
        if username:
            serial = load_serial(username)
            renew_cookie(auth_cookie_name(), username)
            return username

    for cookie_name in html.get_cookie_names():
        if cookie_name.startswith('auth_'):
            try:
                return check_auth_cookie(cookie_name)
            except Exception, e:
                #if html.enable_debug:
                #    html.write('Exception occured while checking cookie %s' % cookie_name)
                #    raise
                #else:
                #pass
                raise

    return ''


def do_login():
    # handle the sent login form
    err = None
    if html.var('_login'):
        try:
            username = html.var('_username', '').rstrip()
            if username == '':
                raise MKUserError('_username', _('No username given.'))

            password = html.var('_password', '')
            if password == '':
                raise MKUserError('_password', _('No password given.'))

            origtarget = html.var('_origtarget')
            # Disallow redirections to:
            #  - logout.py: Happens after login
            #  - side.py: Happens when invalid login is detected during sidebar refresh
            #  - Full qualified URLs (http://...) to prevent redirection attacks
            if not origtarget or "logout.py" in origtarget or 'side.py' in origtarget or '://' in origtarget:
                origtarget = defaults.url_prefix + 'check_mk/'

            # None        -> User unknown, means continue with other connectors
            # '<user_id>' -> success
            # False       -> failed
            result = userdb.hook_login(username, password)
            if result:
                # use the username provided by the successful login function, this function
                # might have transformed the username provided by the user. e.g. switched
                # from mixed case to lower case.
                username = result

                # When single user session mode is enabled, check that there is not another
                # active session
                userdb.ensure_user_can_init_session(username)

                # reset failed login counts
                userdb.on_succeeded_login(username)

                # The login succeeded! Now:
                # a) Set the auth cookie
                # b) Unset the login vars in further processing
                # c) Redirect to really requested page
                create_auth_session(username)

                # Never use inplace redirect handling anymore as used in the past. This results
                # in some unexpected situations. We simpy use 302 redirects now. So we have a
                # clear situation.
                # userdb.need_to_change_pw returns either False or the reason description why the
                # password needs to be changed
                result = userdb.need_to_change_pw(username)
                if result:
                    html.http_redirect('user_change_pw.py?_origtarget=%s&reason=%s' % (html.urlencode(origtarget), result))
                else:
                    html.http_redirect(origtarget)
            else:
                userdb.on_failed_login(username)
                raise MKUserError(None, _('Invalid credentials.'))
        except MKUserError, e:
            html.add_user_error(e.varname, e)
            return "%s" % e

def page_login(no_html_output = False):
    result = do_login()
    if type(result) == tuple:
        return result # Successful login
    elif no_html_output:
        raise MKAuthException(_("Invalid login credentials."))

    if html.mobile:
        import mobile
        return mobile.page_login()

    else:
        return normal_login_page()

def normal_login_page(called_directly = True):
    html.set_render_headfoot(False)
    html.header(_("Check_MK Multisite Login"), javascripts=[], stylesheets=["pages", "login"])

    origtarget = html.var('_origtarget', '')
    if not origtarget and not html.myfile in [ 'login', 'logout' ]:
        origtarget = html.makeuri([])

    # Never allow the login page to be opened in a frameset. Redirect top page to login page.
    # This will result in a full screen login page.
    html.javascript('''if(top != self) {
    window.top.location.href = location;
}''')

    # When someone calls the login page directly and is already authed redirect to main page
    if html.myfile == 'login' and check_auth() != '':
        html.immediate_browser_redirect(0.5, origtarget and origtarget or 'index.py')
        return apache.OK

    html.write('<div id="login">\n')
    html.write('<img id="login_window" src="images/login_window.png" />\n')
    html.write('<div id="version">%s</div>\n' % defaults.check_mk_version)

    html.begin_form("login", method = 'POST', add_transid = False, action = 'login.py')
    html.hidden_field('_login', '1')
    html.hidden_field('_origtarget', html.attrencode(origtarget))
    html.write('<label id="label_user" class="legend" for="_username">%s:</label><br />\n' % _('Username'))
    html.text_input("_username", id="input_user")
    html.write('<label id="label_pass" class="legend" for="_password">%s:</label><br />\n' % _('Password'))
    html.password_input("_password", id="input_pass", size=None)

    if html.has_user_errors():
        html.write('<div id="login_error">')
        html.show_user_errors()
        html.write('</div>\n')

    html.write('<div id="button_text">')
    html.image_button("_login", _('Login'))
    html.write("</div>\n")

    html.write('<div id="foot">Version: %s - &copy; '
               '<a href="http://mathias-kettner.de">Mathias Kettner</a><br /><br />' % defaults.check_mk_version)
    html.write(_('You can use, modify and distribute Check_MK under the terms of the <a href="%s">'
                 'GNU GPL Version 2</a>.' % "http://mathias-kettner.de/gpl.html"))
    html.write("</div>\n")

    html.set_focus('_username')
    html.hidden_fields()
    html.end_form()
    html.write("</div>\n")

    html.footer()
    return apache.OK

def page_logout():
    invalidate_auth_session()

    if config.auth_type == 'cookie':
        html.http_redirect(defaults.url_prefix + 'check_mk/login.py')
    else:
        # Implement HTTP logout with cookie hack
        if not html.has_cookie('logout'):
            html.set_http_header('WWW-Authenticate', 'Basic realm="%s"' % defaults.nagios_auth_name)
            html.set_cookie('logout', '1')
            raise apache.SERVER_RETURN, apache.HTTP_UNAUTHORIZED
        else:
            html.del_cookie('logout')
            html.http_redirect(defaults.url_prefix + 'check_mk/')
