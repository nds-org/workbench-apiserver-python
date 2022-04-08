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
    def retrieve_user_by_username(self, username):
        pass

    @abstractmethod
    def update_user(self, updated_user):
        pass

    @abstractmethod
    def delete_user(self, username):
        pass

    # AppSpecs
    @abstractmethod
    def fetch_all_appspecs_for_user(self, username):
        pass

    @abstractmethod
    def create_system_appspec(self, new_appspec):
        pass
    
    @abstractmethod
    def create_user_appspec(self, new_appspec):
        pass

    @abstractmethod
    def fetch_user_appspecs(self, username):
        pass

    @abstractmethod
    def fetch_system_appspecs(self):
        pass

    @abstractmethod
    def retrieve_user_appspec_by_key(self, username, spec_key):
        pass

    @abstractmethod
    def retrieve_system_appspec_by_key(self, spec_key):
        pass

    @abstractmethod
    def update_user_appspec(self, username, updated_appspec):
        pass

    @abstractmethod
    def update_system_appspec(self, updated_appspec):
        pass

    @abstractmethod
    def delete_user_appspec(self, username, spec_key):
        pass

    @abstractmethod
    def delete_system_appspec(self, spec_key):
        pass

    # UserApps
    @abstractmethod
    def create_userapp(self, new_userapp):
        pass

    @abstractmethod
    def fetch_userapps(self, username):
        pass

    @abstractmethod
    def retrieve_userapp_by_id(self, username, userapp_id):
        pass

    @abstractmethod
    def update_userapp(self, updated_userapp):
        pass

    @abstractmethod
    def delete_userapp(self, username, userapp_id):
        pass

    # Vocabulary
    @abstractmethod
    def fetch_vocab_by_name(self, vocab_name):
        pass

