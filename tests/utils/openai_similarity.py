import os
import pandas as pd
import numpy as np
import openai
from tqdm import tqdm
from config import mongo_db, final_results_coll, retrieval_approach_choice, OPENAI_API_KEY
from utils.knowledge_graph import process_corpus
from utils.miscellaneous import get_body

openai.api_key = OPENAI_API_KEY or os.environ.get('OPENAI_API_KEY', '')


def get_embedding(text, model="text-embedding-3-small"):
    response = openai.Embedding.create(input=text, model=model)
    return response['data'][0]['embedding']


def cosine_similarity(vec1, vec2):
    return np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2))


def openai_rerank(description, cve, c, filtered_funcs):
    coll = c[mongo_db][final_results_coll]
    processed_methods = [
        {
            'body': process_corpus(get_body(f)),
            'file': f['file'],
            'name': f['name'],
        }
        for f in tqdm(filtered_funcs)
    ]
    embedding = get_embedding(description)

    processed_methods_df = pd.DataFrame(processed_methods)
    tqdm.pandas(desc="Calculating similarities")
    processed_methods_df['similarities'] = processed_methods_df['body'].progress_apply(
        lambda x: cosine_similarity(get_embedding(x), embedding)
    )

    res = processed_methods_df.sort_values('similarities', ascending=False)
    top = res.to_dict('records')

    if retrieval_approach_choice != 'no_filter':
        coll.update_one(
            {'cve': cve},
            {'$set': {
                'top-k': [each['name'] for each in top],
                'path': [each['file'] for each in top],
                'scores': [each['similarities'] for each in top],
                'all_file_count': len(filtered_funcs),
            }},
            upsert=True,
        )
    else:
        coll.update_one(
            {'cve': cve},
            {'$set': {
                'top-k': [each['name'] for each in top],
                'all_file_count': len(filtered_funcs),
            }},
            upsert=True,
        )
