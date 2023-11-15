import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import hvac
import base64
import json

class AwxClient():
    def __init__(self, config, param, logger):
        self.logger = logger
        self.config = config
        self.tokenHeader = {}
        self.baseURL = config['awx_base_endpoint']
        self.token_id = 0

        if param.get('awx_auth_type') in ['basic_with_vault_kv2', 'saml_with_vault_kv2']:

            vclient = hvac.Client(config['vault_url'])

            if config.get('vault_role_id') and config.get('vault_secret_id'):
                vclient.auth.approle.login(
                    role_id=config['vault_role_id'],
                    secret_id=config['vault_secret_id'])
                self.logger.debug('AppRole in awx.yaml will be used\n')
            else:
                raise Exception('AppRole information cannot be found')

            user_key = 'user_name'
            if 'awx_vault_user_key' in param:
                user_key = param['awx_vault_user_key']

            pw_key = 'password'
            if 'awx_vault_pw_key' in param:
                pw_key = param['awx_vault_pw_key']

            self.logger.debug('awx_vault_user_key: "%s"\n' % (user_key))
            self.logger.debug('awx_vault_pw_key: "%s"\n' % (pw_key))
            self.logger.debug('mount_point: "%s"\n' % (param.get('awx_vault_backend_name')))
            self.logger.debug('path: "%s"\n' % (param.get('awx_vault_secret_path')))

            awx_cred={}
            awx_cred = vclient.secrets.kv.v2.read_secret_version(
                       mount_point=param.get('awx_vault_backend_name'),
                       path=param.get('awx_vault_secret_path'))
            awx_cred = awx_cred.pop('data', None)

            if not all (type(awx_cred) is dict and 'data' in awx_cred
                        and key in awx_cred['data'] for key in (user_key, pw_key)):
                raise Exception('unexpected configuration for the Vault')

            self.username = awx_cred['data'][user_key]
            self.password = awx_cred['data'][pw_key]

        else:

            self.username = param['awx_user_name']
            self.password = param['awx_password']

        self.param = param.copy()

    def __del__(self):
        if self.tokenHeader == {}:
            return

        if self.param.get('awx_auth_type') in ['saml', 'saml_with_vault_kv2']:
            self.get('/api/logout/')
        else:
            self.delete('/api/v2/tokens/' + self.token_id)

    def getRequestHeader(self):
        s = requests.Session()
        self.session = s

        if self.param.get("awx_auth_type") in ['saml', 'saml_with_vault_kv2']:

            #with SAML

            action_url = ''
            saml_req_c = self.config.get("saml_request_attempts_count", 12) # default: 12 attempts
            saml_req_interval = self.config.get("saml_request_interval", 5) # default: 5 seconds
            data_params = {}
            for try_c in range(saml_req_c):
                if try_c != 0:
                    time.sleep(saml_req_interval)

                rsp = s.get(self.baseURL + '/sso/login/saml/', verify=False, params={'idp': 'myidp'})

                if rsp.status_code != 200:
                    raise Exception('failed to login')

                soup = BeautifulSoup(rsp.text, "html.parser")
                kc_login=soup.find("form", id="kc-form-login")
                if isinstance(kc_login, type(None)):
                    continue # retry

                rsp = s.post(kc_login["action"], verify=False,
                             data={'username': self.username, 'password': self.password, 'credentialId': ''})
                # print('authentication response')

                soup = BeautifulSoup(rsp.text, "html.parser")
                if soup.find("form", id="kc-form-login"):
                    raise Exception('authentication failure')

                for saml_comp in soup.find_all("form"):
                    if ("name", "saml-post-binding") in saml_comp.attrs.items() and "action" in saml_comp.attrs:
                        action_url = saml_comp["action"]
                        form_inputs = saml_comp.find_all("input")
                        for input_item in form_inputs:
                            if input_item["type"] == "hidden":
                                data_params[input_item["name"]] = input_item["value"]
                        break # authentication success

                if action_url != '':
                    break # authentication access
            else:
                raise Exception('authentication failure')

            rsp = s.post(action_url, verify=False, data=data_params)

            awxURLO = urlparse(action_url)
            self.baseURL = awxURLO.scheme + '://' + awxURLO.netloc

            rsp = s.get(self.baseURL + '/api/', verify=False)
            csrf = rsp.cookies.get("csrftoken", domain=awxURLO.hostname)

            if csrf == '':
                raise Exception('failed to get a CSRF token')

            self.tokenHeader = {'Referer': self.baseURL + '/', "X-CSRFToken": csrf}
            rsp = s.get(self.baseURL+'/api/v2/me/', verify=False, headers=self.tokenHeader) # check a CSRF token

        else:

            #without SAML
            rsp = s.post(
                  self.baseURL + '/api/v2/tokens/',
                  verify=False,
                  headers={
                    'Content-Type': 'application/json',
                    'Authorization': 'Basic ' + base64.b64encode((self.username + ':' + self.password).encode())},
                  data={'scope': 'write'})

            if rsp.status_code != 200:
                raise Exception('failed to login')

            json_data = rsp.json()
            self.tokenHeader = {'Authorization': 'Bearer ' + json_data.get("token")}
            self.token_id = json_data.get("id")
            rsp = s.get(self.baseURL+'/api/v2/me/', verify=False, headers=self.tokenHeader) # check a token

    def getJsonTypeHeader(self):
        if self.tokenHeader == {}:
            self.getRequestHeader()
        if "X-CSRFToken" in self.tokenHeader or "Authorization" in self.tokenHeader:
            jsonTypeHeader = self.tokenHeader.copy()
            jsonTypeHeader['Content-Type'] = 'application/json'
            return jsonTypeHeader
        return {}

    def getUnifiedID(self, api_path, name_dict, **kwargs):
        expected_keys = list(name_dict.keys())
        expected_keys.extend(["id", "summary_fields"])

        while not isinstance(api_path, type(None)):
            rsp = self.get(api_path)
            rsp_json = rsp.json()

            if not all (key in rsp_json for key in ("count", "next", "results") ):
                return # not found

            resource_list = rsp_json["results"]
            for resource in resource_list:
                if not all (key in resource for key in expected_keys):
                    continue
                for comp_key in name_dict:
                    if resource[comp_key] != name_dict[comp_key]:
                        break
                else:
                    for additional_name in kwargs:
                        summary_fields = resource["summary_fields"]
                        if not ( additional_name in summary_fields and "name" in summary_fields[additional_name]):
                            break # unexpected field
                        if kwargs[additional_name] and summary_fields[additional_name]["name"] != kwargs[additional_name]:
                            break
                    else:
                        return resource["id"] # found

            api_path = rsp_json["next"]

        return # not found

    def getObjectID(self, api_path, name, **kwargs):
        return self.getUnifiedID(api_path, {"name": name}, **kwargs)

    def post(self, path, data):
        reqHeader = self.getJsonTypeHeader()
        return self.session.post(self.baseURL+path, verify=False, headers=reqHeader, data=data)

    def get(self, path, **kwargs):
        params = {}
        if "params" in kwargs:
            params = {"params": kwargs['params']}

        reqHeader = self.getJsonTypeHeader()
        return self.session.get(self.baseURL+path, verify=False, headers=reqHeader, **params)

    def put(self, path, data):
        reqHeader = self.getJsonTypeHeader()
        return self.session.put(self.baseURL+path, verify=False, headers=reqHeader, data=data)

    def delete(self, path):
        reqHeader = self.getJsonTypeHeader()
        return self.session.delete(self.baseURL+path, verify=False, headers=reqHeader)
    
    def getJobTemplateResult(self, job_template_id):
        req_count = self.config.get("get_job_result_request_attempts_count", 360) # default: 360 attempts
        req_interval = self.config.get("get_job_result_request_interval", 5) # default: 5 seconds
        output_json = {}
        for try_c in range(req_count):
            if try_c != 0:
                time.sleep(req_interval)

            res = self.get("/api/v2/jobs/" + str(job_template_id) + "/")
            
            #Print output of request
            self.logger.debug('Get Response "%s"' % (res.content))
        
            if (not res.ok):
                res.raise_for_status()
           
            #Convert string to json for easier manipulation
            data = res.json()
            #Keep some specific key-value pair
            for item in ('id', 'name', 'status'):
                output_json[item] = data.get(item)

            if data['status'] in ['running', 'pending']:
                continue

            res = self.get(
                    "/api/v2/jobs/" + str(job_template_id) + "/stdout/",
                    params={"format": "txt"})

            #Raise error if status not ok
            if (not res.ok):
                res.raise_for_status()
            output_json['log'] = res.text
            
            if data['status'] in ['running', 'pending']:
                break

        return output_json

    def getPayloadString(self, payload):
        if not payload:
            return None
        return json.dumps(payload)
