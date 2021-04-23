import pkg.config as config
from pkg.etcd import WBEtcd

etcdClient = WBEtcd(host=config.ETCD_HOST, port=config.ETCD_PORT)
