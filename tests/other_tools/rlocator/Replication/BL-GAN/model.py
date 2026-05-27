import torch.nn.functional as F
import math
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data, Batch
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence
from torch.autograd import Variable


class BugReportProcessor(nn.Module):
    def __init__(self, vocab_size, d_model, n_head, num_encoder_layers, dim_feedforward, max_seq_length):
        super(BugReportProcessor, self).__init__()
        self.vocab_size = vocab_size
        self.d_model = d_model
        self.n_head = n_head
        self.num_encoder_layers = num_encoder_layers
        self.dim_feedforward = dim_feedforward
        self.max_seq_length = max_seq_length
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.positional_encoding = nn.Parameter(self._get_positional_encoding(max_seq_length, d_model),
                                                requires_grad=False)
        self.transformer_encoder = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(d_model=d_model, nhead=n_head, dim_feedforward=dim_feedforward,
                                       batch_first=True),
            num_layers=num_encoder_layers, enable_nested_tensor=True
        )

    def forward(self, src):
        src = self.embedding(src) * math.sqrt(self.d_model)  # scale embedding
        src += self.positional_encoding[:src.size(0)]
        src = self.transformer_encoder(src)
        src = src.mean(dim=1)  # Mean pooling
        return src

    def _get_positional_encoding(self, max_len, d_model):
        """Generate and return positional encoding."""
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        return pe


class LSTMPathGenerator(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(LSTMPathGenerator, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)
        self.hidden_size = hidden_size

    def forward(self, bug_report_embedding, hidden_state):
        lstm_out, hidden_state = self.lstm(bug_report_embedding.unsqueeze(1), hidden_state)
        output = self.fc(lstm_out.squeeze(1))
        return F.softmax(output, dim=1), hidden_state

    def init_hidden(self, batch_size):
        h, c = (Variable(torch.zeros(1, batch_size, self.hidden_size)),
                Variable(torch.zeros(1, batch_size, self.hidden_size)))
        return h, c


class GenerativeModule(nn.Module):
    def __init__(self, vocab_size, d_model, n_head, num_encoder_layers, dim_feedforward, max_seq_length,
                 generative_lstm_hidden_size, generative_lstm_output_size):
        super(GenerativeModule, self).__init__()
        self.bug_report_processor = BugReportProcessor(vocab_size, d_model, n_head, num_encoder_layers,
                                                       dim_feedforward,
                                                       max_seq_length)
        self.file_path_generator = LSTMPathGenerator(input_size=d_model, hidden_size=generative_lstm_hidden_size,
                                                     output_size=generative_lstm_output_size)

    def forward(self, x):
        report_embedding = self.bug_report_processor(x)
        out, _ = self.file_path_generator(report_embedding,
                                          self.file_path_generator.init_hidden(report_embedding.shape[0]))
        return out


class CodeEmbeddingLayer(nn.Module):
    def __init__(self, num_node_features, output_dim):
        super().__init__()
        self.gcn1 = GCNConv(num_node_features, output_dim, normalize=False)
        self.gcn2 = GCNConv(output_dim, output_dim)
        self.dropout = nn.Dropout()

    def forward(self, batch):
        x, edge_index, batch_idx = batch.x, batch.edge_index, batch.batch
        x = F.relu(self.gcn1(x, edge_index))
        x = self.dropout(x)
        x = self.gcn2(x, edge_index)
        num_graphs = batch_idx.max().item() + 1  # Get the number of graphs in the batch
        num_nodes_per_graph = (batch_idx == 0).sum().item()  # Assuming equal number of nodes in each graph
        x_reshaped = torch.zeros((num_graphs, num_nodes_per_graph, x.size(1)), device=x.device)
        return x_reshaped


class FilePathEncoder(nn.Module):
    def __init__(self, vocab_size, embedding_dim, hidden_dim):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.embedding = nn.Embedding(num_embeddings=vocab_size, embedding_dim=embedding_dim)
        self.fc = nn.Linear(hidden_dim * 2, hidden_dim)
        self.bilstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)

    def init_hidden(self, batch_size):
        h, c = (Variable(torch.zeros(2, batch_size, self.hidden_dim)),
                Variable(torch.zeros(2, batch_size, self.hidden_dim)))
        return h, c

    def forward(self, filepath_indices):
        embeddings = self.embedding(filepath_indices)
        h_0, c_0 = self.init_hidden(filepath_indices.shape[0])
        output, (h_n, c_n) = self.bilstm(embeddings, (h_0, c_0))
        out = output[:, -1, :]
        rel = F.relu(out)
        final_representation = self.fc(rel)
        return final_representation


class RealPairs(nn.Module):
    def __init__(self, gcn_node_features, gcn_output_dim, path_vocab, path_embedding_dim, path_hidden_dim, input_dim,
                 output_dim):
        super().__init__()
        self.code_embedding_model = CodeEmbeddingLayer(num_node_features=gcn_node_features, output_dim=gcn_output_dim)
        self.file_path_embedding_model = FilePathEncoder(vocab_size=path_vocab, embedding_dim=path_embedding_dim,
                                                         hidden_dim=path_hidden_dim)
        self.fc = nn.Linear(input_dim, output_dim)

    def forward(self, graph_batch, path_batch):
        code_embedding = self.code_embedding_model(graph_batch).mean(-2)
        path_embedding = self.file_path_embedding_model(path_batch)
        code_path_embedding = torch.cat([code_embedding, path_embedding], dim=-1)
        output = self.fc(code_path_embedding)
        return output


class Discriminator(nn.Module):
    def __init__(self, vocab_size, d_model, n_head, num_encoder_layers, dim_feedforward, max_seq_length, input_dim):
        super().__init__()
        self.bug_report_processor = BugReportProcessor(vocab_size, d_model, n_head, num_encoder_layers, dim_feedforward,
                                                       max_seq_length)
        self.fc = nn.Linear(input_dim, 1)

    def forward(self, br_batch, code_path_batch):
        bug_report_embedding = self.bug_report_processor(br_batch)
        br_code_path_embedding = torch.cat([bug_report_embedding, code_path_batch], dim=-1)
        output = self.fc(br_code_path_embedding)
        return F.sigmoid(output)

