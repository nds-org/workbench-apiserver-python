import logging

from pkg.db.datastore import data_store

logger = logging.getLogger('api.v1.vocabulary')


def get_vocabulary_by_name(vocab_name):
    vocabulary = data_store.fetch_vocab_by_name(vocab_name)
    return vocabulary, 200

