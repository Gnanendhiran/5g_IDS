import torch
import torch.nn as nn
import torch.nn.functional as F

NODES_PER_GRAPH = 5
GRAPHS_PER_SEQUENCE = 5

class GATLayer(nn.Module):
    def __init__(self, in_channels, out_channels, heads=1, concat=True, dropout=0.3):
        super().__init__()
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.heads = heads
        self.concat = concat
        self.lin = nn.Linear(in_channels, out_channels * heads, bias=False)
        self.att_src = nn.Parameter(torch.empty(1, heads, out_channels))
        self.att_dst = nn.Parameter(torch.empty(1, heads, out_channels))
        self.bias = nn.Parameter(torch.zeros(out_channels * heads))
        self.dropout = dropout
        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.lin.weight)
        nn.init.xavier_uniform_(self.att_src)
        nn.init.xavier_uniform_(self.att_dst)
        nn.init.zeros_(self.bias)

    def forward(self, x, edge_index):
        n = x.size(0)
        src, dst = edge_index[0], edge_index[1]
        h = self.lin(x).view(n, self.heads, self.out_channels)
        a_src = (h * self.att_src).sum(-1)
        a_dst = (h * self.att_dst).sum(-1)
        alpha = F.leaky_relu(a_src[src] + a_dst[dst], negative_slope=0.2)
        attention = torch.zeros_like(alpha)
        for node in torch.unique(dst):
            mask = dst == node
            attention[mask] = torch.softmax(alpha[mask], dim=0)
        attention = F.dropout(attention, p=self.dropout, training=self.training)
        out = torch.zeros_like(h)
        for e in range(src.numel()):
            out[dst[e]] += attention[e].unsqueeze(-1) * h[src[e]]
        if self.concat:
            out = out.reshape(n, self.heads * self.out_channels)
        else:
            out = out.mean(dim=1)
        return out + self.bias

class SpatialEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.gat1 = GATLayer(91, 128, heads=4, concat=True, dropout=0.3)
        self.gat2 = GATLayer(512, 128, heads=1, concat=False, dropout=0.3)
        self.dropout = nn.Dropout(0.3)
        self.batch_norm = nn.BatchNorm1d(128)

    def forward(self, x, edge_index):
        x = F.elu(self.gat1(x, edge_index))
        x = self.dropout(x)
        x = self.gat2(x, edge_index)
        x = self.batch_norm(x)
        return F.elu(x)

class TemporalEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.gru = nn.GRU(128, 128, num_layers=2, batch_first=True, dropout=0.3)
        self.projection = nn.Linear(128, 128)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        output, _ = self.gru(x)
        return self.dropout(self.projection(output[:, -1, :]))

class HierarchicalFusion(nn.Module):
    def __init__(self):
        super().__init__()
        self.spatial_attention = nn.Linear(128, 1)
        self.temporal_attention = nn.Linear(128, 1)
        self.fusion_layer = nn.Sequential(
            nn.Linear(128, 128), nn.ReLU(), nn.Dropout(0.3), nn.Linear(128, 128)
        )

    def forward(self, spatial, temporal):
        scores = torch.cat([
            self.spatial_attention(spatial),
            self.temporal_attention(temporal)
        ], dim=1)
        weights = torch.softmax(scores, dim=1)
        sw, tw = weights[:, :1], weights[:, 1:2]
        fused = sw * spatial + tw * temporal
        return self.fusion_layer(fused), sw, tw

class HTSTCLGNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.spatial_encoder = SpatialEncoder()
        self.temporal_encoder = TemporalEncoder()
        self.fusion = HierarchicalFusion()
        self.projection_head = nn.Sequential(
            nn.Linear(128, 128), nn.ReLU(), nn.Dropout(0.3), nn.Linear(128, 128)
        )
        self.classifier = nn.Sequential(
            nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.3), nn.Linear(64, 2)
        )

    def forward(self, sequence_x, sequence_edges):
        batch_size = sequence_x.shape[0]
        sequences = []
        for b in range(batch_size):
            graphs = []
            for t in range(GRAPHS_PER_SEQUENCE):
                nodes = self.spatial_encoder(sequence_x[b, t], sequence_edges[b, t])
                graphs.append(nodes.mean(dim=0))
            sequences.append(torch.stack(graphs, dim=0))
        spatial_sequence = torch.stack(sequences, dim=0)
        temporal = self.temporal_encoder(spatial_sequence)
        current_spatial = spatial_sequence[:, -1, :]
        fused, sw, tw = self.fusion(current_spatial, temporal)
        projection = self.projection_head(fused)
        logits = self.classifier(fused)
        return logits, fused, projection, current_spatial, temporal, sw, tw

def load_checkpoint(model, checkpoint_path, device):
    checkpoint = torch.load(checkpoint_path, map_location=device)
    state = checkpoint.get("state_dict", checkpoint.get("model_state_dict", checkpoint)) if isinstance(checkpoint, dict) else checkpoint
    cleaned = {(k[7:] if k.startswith("module.") else k): v for k, v in state.items()}
    missing, unexpected = model.load_state_dict(cleaned, strict=False)
    if missing or unexpected:
        raise RuntimeError(f"Checkpoint mismatch. Missing={missing}, Unexpected={unexpected}")
    return model
