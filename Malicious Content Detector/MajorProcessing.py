import pickle
import string
import re

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from profanity_check import predict, predict_prob

from Trie import TrieNode, find_a_word


def bad_word_exists(trie_root: TrieNode, sentence: str):
    words = sentence.translate(str.maketrans('', '', string.punctuation))
    words = sentence.lower().split(' ')
    for word in words:
        if find_a_word(trie_root, word):
            break
    else:
        return False
    return True


def makeTokens(f):
    tkns_BySlash = str(f.encode('utf-8')).split('/')  # make tokens after splitting by slash
    total_Tokens = []
    for i in tkns_BySlash:
        tokens = str(i).split('-')  # make tokens after splitting by dash
        tkns_ByDot = []
        for j in range(0, len(tokens)):
            temp_Tokens = str(tokens[j]).split('.')  # make tokens after splitting by dot
            tkns_ByDot = tkns_ByDot + temp_Tokens
        total_Tokens = total_Tokens + tokens + tkns_ByDot
    total_Tokens = list(set(total_Tokens))  # remove redundant tokens
    if 'com' in total_Tokens:
        total_Tokens.remove(
            'com')  # removing .com since it occurs a lot of times and it should not be included in our features
    return total_Tokens


def _get_malicious_url_probability(vectorizer, logreg, rf, lgb, url):
    sentence = [url]
    vectorized_sentence = vectorizer.transform(sentence)

    logreg_prob = logreg.predict_proba(vectorized_sentence)[0][0]
    rf_prob = rf.predict_proba(vectorized_sentence)[0][0]
    lgb_prob = 1.0 - lgb.predict(vectorized_sentence)[0]

    return 1.0 - ((logreg_prob + rf_prob + lgb_prob) / 3)


def get_malicious_url_probability(url):
    return _get_malicious_url_probability(vectorizer, logreg_model, rf_model, lgb_model, url)


def get_profanity_probability(sentence):
    return predict_prob([sentence])[0]


def detect_content_type(sentence):
    text_regex = r"^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$"
    email_address_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    phone_number_regex = r"^[a-zA-Z: ]*[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$"
    website_regex = r"^(https?:\/\/)?(www\.)?([a-zA-Z0-9]+(-?[a-zA-Z0-9])*\.)+[\w]{2,}(\/\S*)?$"

    result = 'Undefined'

    if re.search(email_address_regex,sentence):
        result = 'Email Address'
    elif re.search(phone_number_regex,sentence):
        result = 'Phone Number'
    elif re.search(website_regex,sentence):
        result = 'Website URL'
    elif re.search(text_regex,sentence):
        result = 'Text'
    return result


if __name__ == '__main__':
    badwords_trie_root: TrieNode = TrieNode('*')

    with open('badwords.pkl', 'rb') as pickle_file:
        badwords_trie_root: TrieNode = pickle.load(pickle_file)
    # bad_word_exists(badwords_trie_root, 'Fuck you')

    with open('trained_models//lgb_model.pkl', 'rb') as lgb_file:
        lgb_model = pickle.load(lgb_file)
    with open('trained_models//logreg_model.pkl', 'rb') as log_file:
        logreg_model = pickle.load(log_file)
    with open('trained_models//rf_model.pkl', 'rb') as rf_file:
        rf_model = pickle.load(rf_file)

    data = pd.read_csv("URL data/url-dataset.csv", encoding='latin-1')
    corpus = data['url']
    vectorizer = TfidfVectorizer(tokenizer=makeTokens)
    vectorizer.fit_transform(corpus)

    url = 'google.com/search=fuck'
    print(get_malicious_url_probability('ahrenhei.without-transfer.ru/nethost.exe'))
    print(_get_malicious_url_probability(vectorizer, logreg_model, rf_model, lgb_model, url))
    print(get_profanity_probability(url))
