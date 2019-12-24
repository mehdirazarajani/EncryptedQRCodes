import pickle

import pandas as pd
from flask import Flask, jsonify, request
from sklearn.feature_extraction.text import TfidfVectorizer

from MajorProcessing import makeTokens, bad_word_exists, detect_content_type, get_profanity_probability, \
    _get_malicious_url_probability
from Trie import TrieNode

app = Flask(__name__)
badwords_trie_root: TrieNode = TrieNode('*')
vectorizer = TfidfVectorizer(tokenizer=makeTokens)


@app.route('/')
def home():
    return 'Encrypted QR Codes Server is Running'


@app.route('/check_bad_words', methods=['POST'])
def check_bad_words():
    params = request.get_json()
    try:
        if params['secret'] == 'its_very_hard':
            sentence = params['sentence']
    except:
        return jsonify({'message': 'check your params', 'data': {}, 'success': False}), 400
    resultant = bad_word_exists(badwords_trie_root, sentence)
    return jsonify({'message': 'successfully checked bad words', 'success': True, 'data': resultant}), 201


@app.route('/content_type', methods=['POST'])
def get_content_type():
    params = request.get_json()
    try:
        if params['secret'] == 'its_very_hard':
            sentence = params['sentence']
    except:
        return jsonify({'message': 'check your params', 'data': {}, 'success': False}), 400
    resultant = detect_content_type(sentence)
    return jsonify({'message': 'successfully checked bad words', 'success': True, 'data': resultant}), 201


@app.route('/profanity_probability', methods=['POST'])
def get_profanity_probability1():
    params = request.get_json()
    try:
        if params['secret'] == 'its_very_hard':
            sentence = params['sentence']
    except:
        return jsonify({'message': 'check your params', 'data': {}, 'success': False}), 400
    resultant = get_profanity_probability(sentence)
    return jsonify({'message': 'successfully checked bad words', 'success': True, 'data': resultant}), 201


@app.route('/malicious_url_probability', methods=['POST'])
def get_malicious_url_probability1():
    params = request.get_json()
    try:
        if params['secret'] == 'its_very_hard':
            sentence = params['sentence']
        if detect_content_type(sentence) != 'Website URL':
            return jsonify({'message': 'sentence is not of URL format', 'data': {}, 'success': False}), 500
    except:
        return jsonify({'message': 'check your params', 'data': {}, 'success': False}), 400
    try:
        with open('trained_models//lgb_model.pkl', 'rb') as lgb_file:
            lgb_model = pickle.load(lgb_file)
        with open('trained_models//logreg_model.pkl', 'rb') as log_file:
            logreg_model = pickle.load(log_file)
        with open('trained_models//rf_model.pkl', 'rb') as rf_file:
            rf_model = pickle.load(rf_file)
    except:
        return jsonify({'message': 'unable to load model files', 'data': {}, 'success': False}), 500
    resultant = _get_malicious_url_probability(vectorizer, logreg_model, rf_model, lgb_model, sentence)
    return jsonify({'message': 'successfully checked bad words', 'success': True, 'data': resultant}), 201


if __name__ == '__main__':
    with open('badwords.pkl', 'rb') as pkl_file:
        badwords_trie_root = pickle.load(pkl_file)

    data = pd.read_csv("URL data/url-dataset.csv", encoding='latin-1')
    corpus = data['url']
    vectorizer.fit_transform(corpus)

    app.run(debug=True)
