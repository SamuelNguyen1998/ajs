import hvac
import base64
import json

def buildPayload(config, param, logger):
    extra_vars = {}  
    payload = {}
    if param.get('ajs_secret_with_vault_kv2').lower() == "true":
        
        vclient = hvac.Client(config['vault_url'])
        if config.get('vault_role_id') and config.get('vault_secret_id'):
            vclient.auth.approle.login(
            role_id=config['vault_role_id'],
            secret_id=config['vault_secret_id'])
            logger.debug('AppRole in awx.yaml will be used\n')
        else:
            raise Exception('AppRole information cannot be found')

        manager_key = 'manager'
        user_key = 'user_name'
        pw_key = 'password'
        logical_host_key = 'logical_host_name'
        jp1_user_name_key = 'jp1_user_name'
        

        logger.debug('ajs_vault_manager_key: "%s"\n' % (manager_key))
        logger.debug('ajs_vault_user_key: "%s"\n' % (user_key))
        logger.debug('ajs_vault_pw_key: "%s"\n' % (pw_key))
        logger.debug('ajs_vault_logical_host_key: "%s"\n' % (logical_host_key))
        logger.debug('ajs_vault_jp1_user_name_key: "%s"\n' % (jp1_user_name_key))
        logger.debug('mount_point: "%s"\n' % (param.get('ajs_vault_backend_name')))
        logger.debug('path: "%s"\n' % (param.get('ajs_vault_secret_path')))

        ajs_info ={}
        ajs_info = vclient.secrets.kv.v2.read_secret_version(
                   mount_point=param.get('ajs_vault_backend_name'),
                   path=param.get('ajs_vault_secret_path'))
        ajs_info = ajs_info.pop('data', None)

        if not all (type(ajs_info) is dict and 'data' in ajs_info
                    and key in ajs_info['data'] for key in (manager_key, user_key, pw_key, logical_host_key, jp1_user_name_key)):
            raise Exception('unexpected configuration for the Vault')

        payload["ajs_manager"] = ajs_info['data'][manager_key]
        payload["ajs_user_name"] = ajs_info['data'][user_key]
        payload["ajs_password"] = ajs_info['data'][pw_key]
        payload["ajs_logical_host_name"] = ajs_info['data'][logical_host_key]
        payload["ajs_jp1_user_name"] = ajs_info['data'][jp1_user_name_key]  
        
    else:
        payload["ajs_manager"] = param.get('ajs_manager')
        payload["ajs_user_name"] = param.get('ajs_user_name')
        payload["ajs_password"] = param.get('ajs_password')
        payload["ajs_logical_host_name"] = param.get('ajs_logical_host_name')
        payload["ajs_jp1_user_name"] = param.get('ajs_jp1_user_name')

    payload["ajs_service_name"] = param.get('ajs_service_name')
    payload["ajs_unit_name"] = param.get('ajs_unit_name')
    payload["ajs_exec_registration_number"] = param.get('ajs_exec_registration_number')

    extra_vars["extra_vars"] = payload
    return json.dumps(extra_vars)