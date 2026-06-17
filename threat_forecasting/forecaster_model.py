import torch
import torch.nn as nn

class ThreatForecasterLSTM(nn.Module):
    """
    LSTM model architecture for threat occurrence forecasting.
    Input: Sequence of [total_packets, malicious_packets, packet_rate, anomaly_score]
    Output: Probabilities of attacks in the next 1 minute, 5 minutes, and 15 minutes.
    """
    def __init__(self, input_dim=4, hidden_dim=32, num_layers=2, output_dim=3):
        super(ThreatForecasterLSTM, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2 if num_layers > 1 else 0.0)
        self.fc = nn.Linear(hidden_dim, output_dim)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        # Initial hidden and cell states
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(x.device)
        
        out, _ = self.lstm(x, (h0, c0))
        # Decode the hidden state of the last time step
        out = out[:, -1, :]
        out = self.fc(out)
        out = self.sigmoid(out)
        return out
