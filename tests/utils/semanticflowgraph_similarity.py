




import concurrent

import torch
from tqdm import tqdm
from config import mongo_db, repo_dir, retrieval_approach_choice, re_rank_approach_choice, final_results_coll
from utils.evaluation import split_list_into_8_parts, split_list_into_4_parts
from transformers import BertModel, BertTokenizer, RobertaForSequenceClassification, RobertaModel
from transformers import AutoTokenizer, AutoModel, RobertaTokenizer

from utils.miscellaneous import get_body, get_func_hash

card_cnt = 8


def infer(func, description, device, tokenizer, model):
    # Load the UnixCoder tokenizer and model
    body = get_body(func)

    # Tokenize inputs
    inputs = tokenizer.encode_plus(
        description + tokenizer.sep_token + body,
        return_tensors="pt",
        max_length=512,
        truncation=True,
        padding="max_length"
    )

    # Move tensors to the same device as the model
    inputs = {k: v.to(device) for k, v in inputs.items()}

    # Perform inference
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.softmax(logits, dim=-1)
        positive_class_probabilities = probabilities[:, 1]

    # Prepare result
    result, score = func, positive_class_probabilities.item()
    func, file = result['name'], result['file']
    return {'name': func, 'score': score, 'file': file, 'body': body}
    # return ret

def SFG_embedding_similarity(each, index):
    ret = []
    model_name = "other_tools/SemanticFlowGraph/SemanticCodeBERT"
    device = torch.device("cuda:"+str(index) if torch.cuda.is_available() else "cpu")
    tokenizer = RobertaTokenizer.from_pretrained(model_name)
    model = RobertaForSequenceClassification.from_pretrained(model_name).to(device)
    for args in tqdm(each, 'inferencing device '+ str(index)):
        func, description = args
        body = get_body(func)
        # source = remove_comments(source)
        # source = normalize_whitespace(source)

        # inputs1 = tokenizer(lemmatize_sentence(body), return_tensors='pt', truncation=True, padding=True)
        # inputs2 = tokenizer(lemmatize_sentence(description), return_tensors='pt', truncation=True, padding=True)
        inputs = tokenizer.encode_plus(
            description + tokenizer.sep_token + body,  # You might need a separator depending on your data
            return_tensors="pt",
            max_length=512,  # Ensure this matches your training setup
            truncation=True,
            padding="max_length"
        )

        # Move tensors to the same device as the model
        inputs = {k: v.to(device) for k, v in inputs.items()}


        with torch.no_grad():  # Disable gradient calculation
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)  # Convert logits to probabilities

            # Since it's binary classification, assuming the positive class is the second one
            # Adjust the index if your positive class is at a different position
            positive_class_probabilities = probabilities[:, 1]
        # print('Predicted:', func['name'], func['file'], positive_class_probabilities.item())
        result, score = func, positive_class_probabilities.item()
        func, file = result['name'], result['file']
        ret.append({get_func_hash(result): {'name': func, 'score': score, 'file': file}})
    return ret



def semanticflowgraph_rerank(description, cve, c, filtered_funs):
    coll = c[mongo_db][final_results_coll]
    coll.create_index('cve')

    list_to_do = list()
    for filtered_func in filtered_funs:
        list_to_do.append((filtered_func, description))

    print('list to do for', cve+':', len(list_to_do))
    predicted_funcs_path_score = {}
    # initialize_model()
    # model_name = "microsoft/unixcoder-base"
    # device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    # tokenizer = RobertaTokenizer.from_pretrained(model_name)
    # model = RobertaForSequenceClassification.from_pretrained(model_name).to(device)
    # model.eval()
    # for item in tqdm(filtered_funs):
    #     result = infer(item, description, device, tokenizer, model)
    #     func, file = result['name'], result['file']
    #     predicted_funcs_path_score[get_func_hash(result)] = {'name': func, 'score': result['score'], 'file': file}
    if card_cnt == 8:
        parts = split_list_into_8_parts(list_to_do)
    else:
        parts = split_list_into_4_parts(list_to_do)
    with concurrent.futures.ProcessPoolExecutor(card_cnt) as executor:
        # Using a list to store futures
        futures = []
        
        for index, item in enumerate(parts):
            # Submitting the function to be executed with fixed arguments and an element from the list
            future = executor.submit(SFG_embedding_similarity, item, index)
            futures.append(future)
        
        # Gathering results (if needed)
        for future in concurrent.futures.as_completed(futures):
            try:
                list_of_results = future.result()
                for each in list_of_results:
                    for key, items in each.items():
                        predicted_funcs_path_score[key] = items
            except Exception as exc:
                print(f"Generated an exception: {exc}")
    # Sort the predicted functions by score
    predicted_funcs = sorted(predicted_funcs_path_score.items(), key=lambda x: x[1]['score'], reverse=True)
    if retrieval_approach_choice != 'no_filter':
        coll.update_one({'cve': cve}, {'$set': {
            'all_file_count': len(filtered_funs),
            'path': [each[1]['file'] for each in predicted_funcs],
            'top-k': [each[1]['name'] for each in predicted_funcs],
            'scores': [each[1]['score'] for each in predicted_funcs]

        }}, upsert=True)
    else:
        coll.update_one({'cve': cve}, {'$set': {
            'all_file_count': len(filtered_funs),
            'top-k': [each[1]['name'] for each in predicted_funcs],
        }}, upsert=True)