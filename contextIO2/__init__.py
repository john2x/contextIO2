try:
    import json
except ImportError:
    # JSON module introduced in Python 2.6, Google AppEngine still
    # uses Python 2.5
    from django.utils import simplejson as json
import re
from urllib import urlencode, quote
from oauth2 import Request, Consumer, Client, SignatureMethod_HMAC_SHA1 as sha1

from util import as_bool, as_datetime, process_person_info, uncamelize

class RequestError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        return super(RequestError, self).__init__(message)

class ContextIO(object):
    url_base = "https://api.context.io"

    def __init__(self, consumer_key, consumer_secret, timeout=None):
        self.consumer = Consumer(key=consumer_key, secret=consumer_secret)
        self.client = Client(self.consumer, timeout=timeout)
        self.client.set_signature_method(sha1())
        self.base_uri = '2.0'

    def request_uri(self, uri, method="GET", params=None, headers=None, data={}):
        if params is None:
            params = {}
        if headers is None:
            headers = {}
        url = '/'.join((self.url_base, self.base_uri, uri))
        response, body = self.request(url, method, params, headers, data=data)
        status = int(response['status'])

        if status >= 200 and status < 300:
            # file content doesn't return json
            if re.match(r'accounts/\w+/files/\w+/content', uri):
                return body
            # message source doesn't return json
            if re.match(r'accounts/\w+/messages/\w+/source', uri):
                return body
            body = json.loads(body)
            return body
        else:
            self.handle_request_error(response, body)

    def request(self, url, method, params, headers, data=''):
        body = ''
        if method == 'GET' and params:
            url += '?' + urlencode(params)
        elif method == 'POST' and params:
            body = urlencode(params, doseq=True)
        if data:
            body = json.dumps(data)
        print method + ' ' + url
        return self.client.request(url, method, headers=headers, body=body)

    def get_accounts(self, **params):
        params = Resource.sanitize_params(params, ['email', 'status', 'status_ok', 'limit', 'offset'])
        return [Account(self, obj) for obj in self.request_uri('accounts', params=params)]

    def get_account(self, account_id):
        return Account(self, self.request_uri('accounts/%s' % account_id))

    def post_account(self, email, **params):
        params = Resource.sanitize_params(params, ['first_name', 'last_name'])
        params['email'] = email
        return Account(self, self.request_uri('accounts', method="POST", params=params))

    def delete_account(self, account_id):
        pass

    def put_account(self, first_name=None, last_name=None):
        pass

    def get_connect_tokens(self):
        return [ConnectToken(self, obj) for obj in self.request_uri('connect_tokens')]

    def get_connect_token(self, token):
        obj = self.request_uri('connect_tokens/%s' % token)
        return ConnectToken(self, obj)

    def post_connect_token(self, callback_url, **params):
        params = Resource.sanitize_params(params, ['service_level', 'email', 'first_name', 'last_name',
                                                   'source_callback_url', 'source_sync_flags', 'source_raw_file_list'])
        params['callback_url'] = callback_url
        resp = self.request_uri('connect_tokens', method='POST', params=params)
        token = resp['token']
        redirect_url = resp['browser_redirect_url']
        return (token, redirect_url)

    def handle_request_error(self, response, body):
        status_code = int(response['status'])
        try:
            body = json.loads(body)
            raise RequestError(status_code, 'HTTP %(status)s - %(type)s %(code)s: %(message)s' % { 'status': response['status'], 'type': body['type'], 'code': body['code'], 'message': body['value']})
        except (ValueError, TypeError, KeyError):
            raise RequestError(status_code, 'HTTP %(status)s: %(body)s' % {'status':response['status'], 'body':body})

class Resource(object):
    def __init__(self, parent, base_uri, defn):
        defn = uncamelize(defn)

        for k in self.__class__.keys:
            if k in defn:
                setattr(self, k, defn[k])
            else:
                setattr(self, k, None)

        self.parent = parent
        try:
            self.base_uri = quote(base_uri.format(**defn))
        except:
            self.base_uri = quote(base_uri.replace('{','%(').replace('}',')s') % defn)

    def uri_for(self, *elems):
        return '/'.join([self.base_uri] + list(elems))

    def request_uri(self, uri_elems, method="GET", params=None, data=None):
        if params is None:
            params = {}
        uri = self.uri_for(uri_elems)
        return self.parent.request_uri(uri, method=method, params=params, data=data)

    @staticmethod
    def sanitize_params(params, clean_keys):
        return dict((k, params[k]) for k in clean_keys if k in params)

class Account(Resource):
    keys = ['username', 'first_name', 'last_name', 'created', 'password_expired', 'sources', 'suspended', 'id', 'email_addresses']

    def __init__(self, parent, defn):
        super(Account, self).__init__(parent, 'accounts/{id}', defn)

        self.suspended = as_bool(self.suspended)
        self.password_expired = as_bool(self.password_expired)

    def get_contacts(self, **params):
        params = Resource.sanitize_params(params, ['search', 'active_before', 'active_after', 'limit', 'offset'])
        return [Contact(self, obj) for obj in self.request_uri('contacts', params=params).get('matches')]

    def get_email_addresses(self):
        return self.request_uri('email_addresses')

    def get_files(self, **params):
        params = Resource.sanitize_params(params, ['name', 'email', 'to', 'from', 'cc', 'bcc', 'date_before', 'date_after', 'indexed_before', 'indexed_after', 'group_by_revisions', 'limit', 'offset'])
        return [File(self, obj) for obj in self.request_uri('files', params=params)]

    def get_file(self, file_id):
        obj = self.request_uri('files/%s' % file_id)
        return File(self, obj)

    def get_messages(self, **params):
        params = Resource.sanitize_params(params, ['subject', 'email', 'to', 'from', 'cc', 'bcc', 'date_before', 'date_after', 'indexed_before', 'indexed_after', 'include_body', 'include_headers', 'body_type', 'limit', 'offset', 'folder'])
        for key in ['include_headers', 'include_body']:
            if key in params:
                params[key] = '1' if params[key] is True else '0'

        return [Message(self, obj) for obj in self.request_uri('messages', params=params)]

    def get_message(self, message_id, **params):
        params = Resource.sanitize_params(params, ['include_body', 'include_headers', 'include_flags', 'body_type'])
        for key in ['include_headers', 'include_body']:
            if key in params:
                params[key] = '1' if params[key] is True else '0'
        obj = self.request_uri('messages/%s' % message_id, params=params)
        return Message(self, obj)

    def get_sources(self):
        return self.request_uri('sources')

    def post_source(self, email, server, username, use_ssl=True, port='993', type='imap', **params):
        params = Resource.sanitize_params(params, ['service_level', 'sync_period', 'password', 'provider_token', 'provider_token_secret', 'provider_consumer_key'])
        params['email'] = email
        params['server'] = server
        params['username'] = username
        params['port'] = port
        params['type'] = type
        params['use_ssl'] = '1' if use_ssl is True else '0'
        return self.request_uri('sources', method='POST', params=params)

    def get_folders(self, label='0'):
        return [Folder(self, obj, label=label) for obj in self.request_uri('sources/%s/folders' % label)]

    def put_folder(self, label, folder_path, **params):
        params = Resource.sanitize_params(params, ['delim'])
        return self.request_uri('sources/%s/folders/%s' % (label, folder_path), method='PUT', params=params)

    def get_sync(self):
        return self.request_uri('sync')

    def post_sync(self):
        return self.request_uri('sync', method='POST')

    def get_webhooks(self):
        return self.request_uri('webhooks')

class Contact(Resource):
    keys = ['count', 'thumbnail', 'email', 'name']

    def __init__(self, parent, defn):
        super(Contact, self).__init__(parent, 'contacts/{email}',  defn)

    def get_files(self, **params):
        params = Resource.sanitize_params(params, ['limit', 'offset'])
        return self.request_uri('files', params=params)

    def get_messages(self, **params):
        params = Resource.sanitize_params(params, ['limit', 'offset'])
        return self.request_uri('messages', params=params)

    def get_threads(self, **params):
        params = Resource.sanitize_params(params, ['limit', 'offset'])
        return self.request_uri('threads', params=params)

class File(Resource):
    keys = ['person_info', 'occurrences', 'body_section', 'addresses', 'file_name', 'email_message_id', 'supports_preview', 'gmail_thread_id', 'file_id', 'gmail_message_id', 'date', 'file_name_structure', 'size', 'type', 'message_id', 'subject']

    def __init__(self, parent, defn):
        super(File, self).__init__(parent, 'files/{file_id}', defn)

        if 'person_info' in defn:
            person_info, to, frm = process_person_info(parent, defn['person_info'], defn['addresses'])

            self.person_info = person_info
            self.addresses = {
                'to': to,
                'from': frm
            }
            self.date = as_datetime(self.date)

    def get_changes(self, file_id=None):
        if file_id:
            if isinstance(file_id, File):
                file_id = file_id.file_id
            return self.request_uri('changes/' + file_id)

        else:
            return self.request_uri('changes')

    def get_content(self):
        return self.request_uri('content')

    def get_related(self):
        return self.request_uri('related')

    def get_revisions(self):
        return self.request_uri('revisions')

class Thread(Resource):
    keys = ['email_message_ids', 'person_info', 'messages']
    email_message_ids = None
    messages = None

    def __init__(self, parent, defn):
        defn['message_id'] = parent.message_id
        super(Thread, self).__init__(parent, 'messages/{message_id}/thread', defn)
        self.messages = None
        self.person_info = parent.person_info
        self.email_message_ids = defn['email_message_ids']
        self.get_messages(defn['messages'])
        self.files = []
        if 'files' in defn:
            self.files = [File(self.parent, f) for f in defn['files']]

    def get_messages(self, messages):
        if self.messages is None:
            self.messages = []
            for message in messages:
                self.messages.append(Message(self.parent.parent, message))
            for message in self.messages:
                message.thread = self
        return self.messages

class Message(Resource):
    keys = ['body', 'headers', 'date', 'subject', 'addresses', 'files', 'message_id', 'email_message_id', 'gmail_message_id', 'gmail_thread_id', 'person_info']
    body = None
    flags = None
    headers = None
    thread = None
    source = None
    folders = None

    def __init__(self, parent, defn):
        super(Message, self).__init__(parent, 'messages/{message_id}', defn)

        person_info, to, frm = process_person_info(parent, defn['person_info'], defn['addresses'])
        self.person_info = person_info
        self.addresses = {
            'to': to,
            'from': frm
        }
        self.date = as_datetime(self.date)

        self.files = []
        if 'files' in defn:
            self.files = [File(self.parent, f) for f in defn['files']]

        if 'headers' in defn:
            self.process_headers(defn['headers'])

    def process_headers(self, response):
        hlist = []
        for line in response.strip().splitlines():
            if re.search('^\s', line):
                hlist[-1][1] += ' ' + line.strip()
            else:
                key, value = line.split(':', 1)
                hlist.append([key, value.strip()])

        self.headers = {}
        for h in hlist:
            key, value = h

            if key not in self.headers:
                self.headers[key] = value
            else:
                if isinstance(self.headers[key], list):
                    self.headers[key].append(value)
                else:
                    v = self.headers[key]
                    self.headers[key] = [v] + [value]

    def get_body(self):
        if self.body is None:
            self.body = self.request_uri('body')
        return self.body

    def get_flags(self):
        if self.flags is None:
            self.flags = self.request_uri('flags')
        return self.flags

    def get_headers(self):
        if self.headers is None:
            self.headers = self.request_uri('headers')
        return self.headers

    def get_source(self):
        if self.source is None:
            self.source = self.request_uri('source')
        return self.source

    def get_thread(self):
        if self.thread is None:
            self.thread = Thread(self, self.request_uri('thread'))
        return self.thread

    def get_folders(self):
        folders = self.request_uri('folders')
        folders = [Folder(self.parent, obj) for obj in folders]
        self.folders = folders
        return folders

    def edit_folders(self, add=None, remove=None):
        if add is None:
            add = []
        if remove is None:
            remove = []
        if not isinstance(add, list):
            add = [add]
        if not isinstance(remove, list):
            remove = [remove]
        params = {
            'add[]': add,
            'remove[]': remove
        }
        params = Resource.sanitize_params(params, ['add[]', 'remove[]'])
        self.request_uri('folders', method='POST', params=params)

    def set_folders(self, folders):
        data = []
        for f in folders:
            if isinstance(f, Folder):
                if f.name is None and f.symbolic_name is None:
                    continue
                if f.name is None:
                    data.append({'symbolic_name': f.symbolic_name})
                else:
                    data.append({'name': f.name})
            elif isinstance(f, str):
                data.append({'name': f})
            else:
                data.append(f)
        self.request_uri('folders', method='PUT', data=data)

class ConnectToken(Resource):
    keys = ['token', 'email', 'created', 'used', 'callback_url', 'service_level', 'first_name', 'last_name', 'account']

    def __init__(self, parent, defn):
        super(ConnectToken, self).__init__(parent, 'connect_tokens/{token}', defn)
        if defn['account']:
            self.account = Account(self.parent, defn['account'])

class Folder(Resource):
    keys = ['name', 'attributes', 'delim', 'nb_messages', 'nb_unseen_messages', 'symbolic_name']
    name = None
    symbolic_name = None
    delim = None
    attributes = None
    nb_messages = None
    nb_unseen_messages = None
    label = None
    messages = None

    def __init__(self, parent, defn, label='0'):
        defn['label'] = label
        super(Folder, self).__init__(parent, 'sources/{label}/folders/{name}', defn)

    def get_messages(self, **params):
        params = Resource.sanitize_params(params, ['subject', 'email', 'to', 'from', 'cc', 'bcc', 'date_before', 'date_after', 'indexed_before', 'indexed_after', 'include_body', 'include_headers', 'body_type', 'limit', 'offset', 'folder'])
        for key in ['include_headers', 'include_body']:
            if key in params:
                params[key] = '1' if params[key] is True else '0'

        try:
            messages = [Message(self.parent, obj) for obj in self.request_uri('messages', params=params)]
            self.messages = messages
        except RequestError, e:
            if e.status_code == 503:
                self.messages = []
            else:
                raise e
        return self.messages

