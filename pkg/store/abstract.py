from abc import ABC, abstractmethod


class AbstractStore(ABC):

    # UserAccounts
    @abstractmethod
    def create_user(self, new_user):
        pass

    @abstractmethod
    def fetch_users(self):
        pass

    @abstractmethod
    def retrieve_user_by_namespace(self, namespace):
        pass

    @abstractmethod
    def update_user(self, updated_user):
        pass

    @abstractmethod
    def delete_user(self, namespace):
        pass

    # AppSpecs
    @abstractmethod
    def fetch_all_appspecs_for_user(self, namespace):
        pass

    @abstractmethod
    def create_system_appspec(self, new_appspec):
        pass
    
    @abstractmethod
    def create_user_appspec(self, new_appspec):
        pass

    @abstractmethod
    def fetch_user_appspecs(self, namespace):
        pass

    @abstractmethod
    def fetch_system_appspecs(self):
        pass

    @abstractmethod
    def retrieve_user_appspec_by_key(self, namespace, spec_key):
        pass

    @abstractmethod
    def retrieve_system_appspec_by_key(self, spec_key):
        pass

    @abstractmethod
    def update_user_appspec(self, namespace, updated_appspec):
        pass

    @abstractmethod
    def update_system_appspec(self, updated_appspec):
        pass

    @abstractmethod
    def delete_user_appspec(self, namespace, spec_key):
        pass

    @abstractmethod
    def delete_system_appspec(self, spec_key):
        pass

    # UserApps
    @abstractmethod
    def create_userapp(self, new_userapp):
        pass

    @abstractmethod
    def fetch_userapps(self, namespace):
        pass

    @abstractmethod
    def retrieve_userapp_by_id(self, namespace, userapp_id):
        pass

    @abstractmethod
    def update_userapp(self, updated_userapp):
        pass

    @abstractmethod
    def delete_userapp(self, namespace, userapp_id):
        pass

    # Vocabulary
    @abstractmethod
    def fetch_vocab_by_name(self, vocab_name):
        pass

