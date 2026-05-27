mongodb_host = 
mongodb_port = 
mongo_db = 
MONGO_USER= ''
MONGO_PWD = ''
MONGO_AUTH = ''
data_file = 
repo_dir = 
threshold= 0.1

repo_dir = '/workspace/maven_repos/'
threshold = 0.5
# re_rank_approach_choice = 'none'
re_rank_approach_choice = 'wkg'
# re_rank_approach_choice = 'blizzard'
# re_rank_approach_choice = 'bert'
# re_rank_approach_choice = 'knowledge graph'
# re_rank_approach_choice = 'tf-idf'
# re_rank_approach_choice = 'w2v'
# re_rank_approach_choice = 'bm25'
re_rank_approach_choice = 'openai'
re_rank_approach_choice = 'unixcoder'
re_rank_approach_choice = 'semanticflowgraph'
re_rank_approach_choice = 'vulf'


retrieval_approach_choice = 'no_filter'
# retrieval_approach_choice = 'fine_tuned_bert'
# retrieval_approach_choice = 'filter_first_patch_only'
# retrieval_approach_choice = 'filter_first'


query_expansion_choice = 'description_only'
# query_expansion_choice = 'concate'
# query_expansion_choice = 'repeat'
# dataset= 'real_world'
dataset= 'benchmark'

# dataset = None
if dataset == 'real_world':
    final_results_coll = retrieval_approach_choice+'__'+query_expansion_choice+'__'+re_rank_approach_choice+'__'+dataset
    fine_tuned_bert_folder = 'real_world_results'
    dataset_name = 'data/real-world.csv'
elif dataset == 'benchmark':
    final_results_coll = retrieval_approach_choice+'__'+query_expansion_choice+'__'+re_rank_approach_choice
    fine_tuned_bert_folder = 'evaluation_results_function_1-100_big_top100'
    dataset_name= 'data/filtered_cve_with_link.csv'
working_dir = '.'
javaparser_path = working_dir+'/libs/javaParser/rootCauseLocator/target/rootCauseLocator-1.0-SNAPSHOT-jar-with-dependencies.jar'
blizzard_path = working_dir+'/other_tools/BLIZZARD-Replication-Package-ESEC-FSE2018-master/Corpus/ecf/'