import torch
from datasets import load_dataset
from torch.utils.data import DataLoader
from comex.codeviews.combined_graph.combined_driver import CombinedDriver
from torch_geometric.data import Data, Batch
from torch_geometric.utils.convert import from_networkx
from transformers import AutoTokenizer
from model import Discriminator, GenerativeModule, RealPairs
import torch.optim as optim
from torch import nn
from tqdm import tqdm

node_type_dict = dict()
node_type_counter = 1
file_path_dict = dict()
file_path_counter = 1
max_path_length = 40


def file_path_tokenizer(file_path):
    global file_path_counter
    tokens = []
    for item in file_path.split("/"):
        if len(item) > 0:
            if item not in file_path_dict:
                file_path_dict[item] = file_path_counter
                file_path_counter += 1
            tokens.append(file_path_dict[item])
    tokens = tokens[:max_path_length]
    return tokens + [0] * (max_path_length - len(tokens))


def collate_fn(data):
    bug_reports = []
    code_graphs = []
    file_path = []
    global node_type_counter
    for data_item in data:
        bug_reports.append(data_item['title'] + " " + data_item['body'] if data_item['body'] is not None else "")
        graph_ast = CombinedDriver(
            src_language="java",
            src_code=data_item['file_content'], codeviews=graph_generator_config).AST
        nodes_features = []
        for node in graph_ast.nodes:
            node_type = graph_ast.nodes[node]['node_type']
            if node_type not in node_type_dict:
                node_type_dict[node_type] = node_type_counter
                node_type_counter += 1
            nodes_features.append([node_type_dict[node_type]])
        graph_data = from_networkx(graph_ast)
        code_graphs.append(Data(x=torch.tensor(nodes_features, dtype=torch.float), edge_index=graph_data.edge_index))
        file_path.append(file_path_tokenizer(data_item['updated_file']))
    return {
        'bug_reports':
            tokenizer(bug_reports, max_length=512, truncation=True, padding='max_length', return_tensors='pt')[
                'input_ids'],
        'code_graphs': code_graphs,
        'file_path': torch.tensor(file_path)
    }


def get_models():
    vocab_size = 50000
    d_model = 512
    n_head = 2
    num_encoder_layers = 2
    dim_feedforward = 256
    max_seq_length = 512
    generative_lstm_hidden_size = 128
    generative_lstm_output_size = 128
    gcn_node_features = 1
    gcn_output_dim = 128
    path_vocab = 10000
    path_embedding_dim = 128
    path_hidden_dim = 256
    real_pair_input_dim = 384
    real_pair_output_dim = 128
    discriminator_input_dim = 640
    discriminator = Discriminator(vocab_size, d_model, n_head, num_encoder_layers, dim_feedforward, max_seq_length,
                                  discriminator_input_dim)
    generator = GenerativeModule(vocab_size, d_model, n_head, num_encoder_layers, dim_feedforward, max_seq_length,
                                 generative_lstm_hidden_size, generative_lstm_output_size)
    real_pair_embedding = RealPairs(gcn_node_features, gcn_output_dim, path_vocab, path_embedding_dim, path_hidden_dim,
                                    real_pair_input_dim, real_pair_output_dim)
    return generator, discriminator, real_pair_embedding


if __name__ == "__main__":
    # global node_type_counter
    EPOCH = 10
    BATCH_SIZE = 4
    learning_rate_generator = 0.001
    learning_rate_discriminator = 0.001
    ds = load_dataset("Partha117/apache_bugs_with_content")
    tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
    ds = ds['train']
    target_columns = ['title', 'body', 'file_content', 'updated_file']
    dropped_columns = list(set(ds.column_names) - set(target_columns))
    ds = ds.remove_columns(dropped_columns)
    graph_generator_config = {
        "AST": {
            "exists": True,
            "collapsed": False
        },
        "DFG": {
            "exists": False
        },
        "CFG": {
            "exists": False
        }
    }
    g = torch.Generator()
    g.manual_seed(7)
    dataloader = DataLoader(ds, batch_size=BATCH_SIZE,
                            shuffle=True, collate_fn=collate_fn, generator=g)
    generator, discriminator, real_pair_embedding_model = get_models()
    g_optimizer = optim.Adam(generator.parameters(), lr=learning_rate_generator)
    d_optimizer = optim.Adam(list(discriminator.parameters()) + list(real_pair_embedding_model.parameters()),
                             lr=learning_rate_discriminator)
    criterion = nn.BCEWithLogitsLoss()
    pbar = tqdm(dataloader)
    for epoch in range(EPOCH):
        for batch in pbar:
            graph_batch = Batch.from_data_list(batch['code_graphs'])
            real_pair_embedding = real_pair_embedding_model(graph_batch, batch['file_path'])
            real_data_output = discriminator(batch['bug_reports'], real_pair_embedding)
            fake_paths = generator(batch['bug_reports'])
            fake_data_output = discriminator(batch['bug_reports'], fake_paths.detach())

            real_loss = criterion(real_data_output, torch.ones_like(real_data_output))
            generated_loss = criterion(fake_data_output, torch.zeros_like(fake_data_output))
            d_loss = real_loss + generated_loss

            d_optimizer.zero_grad()
            d_loss.backward()
            d_optimizer.step()

            output = discriminator(batch['bug_reports'], fake_paths)
            generator_loss = criterion(output, torch.ones_like(output))

            g_optimizer.zero_grad()
            generator_loss.backward()
            g_optimizer.step()
            pbar.set_description(f"Generator loss {generator_loss.detach()} Discriminator loss {d_loss.detach()}")
    torch.save(generator.state_dict(), "Generator.pt")
    torch.save(discriminator.state_dict(), "Discriminator.pt")
    torch.save(real_pair_embedding_model.state_dict(), "RealPairEmbedding.pt")
