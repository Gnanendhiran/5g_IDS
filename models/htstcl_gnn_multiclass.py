import torch
import torch.nn as nn
from torch_geometric.data import Batch
from torch_geometric.nn import global_mean_pool

from .spatial_encoder import SpatialEncoder
from .temporal_encoder import TemporalEncoder
from .hierarchical_fusion import HierarchicalFusion


class HTSTCL_GNN_Multiclass(nn.Module):
    """
    Multiclass Hierarchical Spatio-Temporal Contrastive Learning Graph Neural Network (HTSTCL-GNN)
    for 5G Wireless Intrusion Detection.
    
    Supports:
      1. Dual-head architecture:
         - Binary Head (Benign vs Malicious) [2 logits]
         - Multiclass Head (9 genuine 5G-NIDD classes) [9 logits]
      2. 4-Head GAT Spatial Encoder
      3. 2-Layer GRU Temporal Sequence Encoder
      4. Spatio-Temporal Attention Fusion
    """

    def __init__(
        self,
        input_dim=91,
        hidden_dim=128,
        embedding_dim=128,
        num_classes=9,
        gru_layers=2,
        dropout=0.3
    ):
        super().__init__()

        self.input_dim = input_dim
        self.embedding_dim = embedding_dim
        self.num_classes = num_classes

        # Spatial Encoder (GAT)
        self.spatial_encoder = SpatialEncoder(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            output_dim=embedding_dim,
            heads=4,
            dropout=dropout
        )

        # Temporal Encoder (GRU)
        self.temporal_encoder = TemporalEncoder(
            input_dim=embedding_dim,
            hidden_dim=embedding_dim,
            num_layers=gru_layers,
            dropout=dropout,
            bidirectional=False
        )

        # Hierarchical Fusion
        self.fusion = HierarchicalFusion(
            embedding_dim=embedding_dim,
            dropout=dropout
        )

        # Contrastive Projection Head
        self.projection_head = nn.Sequential(
            nn.Linear(embedding_dim, embedding_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embedding_dim, embedding_dim)
        )

        # Binary Classifier Head (Benign vs Malicious)
        self.binary_classifier = nn.Sequential(
            nn.Linear(embedding_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 2)
        )

        # Multiclass Classifier Head (9 genuine 5G-NIDD classes)
        self.multiclass_classifier = nn.Sequential(
            nn.Linear(embedding_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes)
        )

    def forward(self, batch_sequences):
        """
        Forward pass for a batch of graph sequences.
        batch_sequences: list of sequences, where each sequence is a list of 5 PyG Data graphs.
        """
        device = next(self.parameters()).device
        batch_size = len(batch_sequences)
        sequence_length = len(batch_sequences[0])

        temporal_embeddings = []

        # Process each temporal step across the entire batch
        for time_step in range(sequence_length):
            graphs_at_t = [batch_sequences[b][time_step] for b in range(batch_size)]
            batched_graph = Batch.from_data_list(graphs_at_t).to(device)

            # Spatial GAT Encoding
            node_embeddings = self.spatial_encoder(
                batched_graph.x,
                batched_graph.edge_index
            )

            # Global Mean Pooling per graph
            graph_embeddings = global_mean_pool(
                node_embeddings,
                batched_graph.batch
            )

            temporal_embeddings.append(graph_embeddings)

        # Stack into [Batch, Sequence, Embedding]
        temporal_input = torch.stack(temporal_embeddings, dim=1)

        # Temporal GRU Encoding
        temporal_embedding = self.temporal_encoder(temporal_input)

        # Current Spatial Representation (last graph in window)
        current_spatial = temporal_input[:, -1, :]

        # Spatio-Temporal Attention Fusion
        fused_embedding, spatial_weight, temporal_weight = self.fusion(
            current_spatial,
            temporal_embedding
        )

        # Contrastive Projection
        projection = self.projection_head(fused_embedding)

        # Classifications
        binary_logits = self.binary_classifier(fused_embedding)
        multiclass_logits = self.multiclass_classifier(fused_embedding)

        return {
            "logits": multiclass_logits,
            "multiclass_logits": multiclass_logits,
            "binary_logits": binary_logits,
            "embedding": fused_embedding,
            "projection": projection,
            "spatial_embedding": current_spatial,
            "temporal_embedding": temporal_embedding,
            "spatial_weight": spatial_weight,
            "temporal_weight": temporal_weight
        }
