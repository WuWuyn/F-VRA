
from main.fine_tune_function import read_dataset
from config import dataset_name

def output_gt_funcs():
    for i, each in enumerate(read_dataset(dataset_name)):
        if each['same_location'] == 'na':
            # print(each['methods'])
            methods = each['methods']
            print(each['cve']+','+'|'.join([each.split(':')[-1].split('(')[0] for each in methods.split(';')])+','+'|'.join([each.split(':')[0].split('.')[-1] for each in methods.split(';')]))