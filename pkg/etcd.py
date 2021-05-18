import logging

import etcd
import json
import bcrypt

import pkg.config as config


class WBEtcd:
    def __init__(self, host='127.0.0.1', port=4001):
        self.client = etcd.Client(host=host, port=port)
        # wont let you run sensitive commands on non-leader machines, default is true
        #client = etcd.Client(host='127.0.0.1', port=4003, allow_redirect=False)
        # client = etcd.Client(
        #    host='127.0.0.1',
        #    port=4003,
        #    allow_reconnect=True,
        #    protocol='https',)

    def getSystemServices(self):
        def get_index(items):
            return items.get('modifiedIndex')

        key = config.ETCD_BASE_PATH+"/services"
        try:
            results = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''
        services = []

        for item in sorted(results._children, key=get_index):
            json_item = json.loads(item['value'])
            json_item['catalog'] = 'system'
            services.append(json_item)

        return services

    def getUserServices(self):
        def get_index(items):
            return items.get('modifiedIndex')

        # need to get uid
        uid = 'temp_id'
        key = config.ETCD_BASE_PATH+"/accounts/"+uid+"/services"
        try:
            results = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''
        services = []

        for item in sorted(results._children, key=get_index):
            json_item = json.loads(item['value'])
            json_item['catalog'] = 'user'
            services.append(json_item)

        return services

    def getAllServices(self):
        services = self.getSystemServices()
        services.append(self.getUserServices())

        return services

    def getServiceWithId(self, service_id):
        key = config.ETCD_BASE_PATH+"/services/"+service_id
        try:
            result = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''

        return json.loads(result.value)

    def getAccountInfo(self, account_id):
        key = config.ETCD_BASE_PATH+"/accounts/"+account_id+"/account"
        try:
            result = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''

        return json.loads(result.value)

    def setAccountInfo(self, account_info):
        key = config.ETCD_BASE_PATH+"/accounts/"+account_info['id']+"/account"

        password = account_info['password']
        hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        account_info['password'] = hashed.decode()
        print(account_info)

        try:
            self.client.write(key, json.dumps(account_info))
            return True
        except NameError:
            return False

    def deleteAccountInfo(self, account_id):
        key = config.ETCD_BASE_PATH+"/accounts/"+account_id+"/account"
        try:
            self.client.delete(key)
            return True
        except etcd.EtcdKeyNotFound:
            return ''

    def checkPassword(self, user_id, password):
        key = config.ETCD_BASE_PATH+"/accounts/"+user_id+"/account"

        try:
            result = self.client.read(key)
            result_value = json.loads(result.value)
            hashed = result_value.get('password')

            if bcrypt.checkpw(password.encode('utf8'), hashed.encode()):
                return True
            else:
                return False
        except etcd.EtcdKeyNotFound:
            return False
        except ValueError:
            return False
