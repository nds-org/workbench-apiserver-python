import logging

from bson import ObjectId
from pkg import config

import json
import connexion


# TODO: v2
VOCABULARIES_COLLECTION_NAME = 'vocabularies'



def list_vocabularies():
    return 501


def create_vocabulary(vocabulary):
    return 501


def get_vocabulary_by_name(vocab_name):
    return 501


def update_vocabulary(vocab_name, vocabulary):
    return 501


def delete_vocabulary(vocab_name):
    return 501






VOCABULARY_SUFFIX = '/vocabularies'
VOCABULARY_BASE_PATH = config.ETCD_BASE_PATH + VOCABULARY_SUFFIX


def search():
    return 501
