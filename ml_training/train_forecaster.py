import os
import joblib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import MinMaxScaler

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainForecaster")

# 1. Dataset Class for sequential lookahead windows
class NetworkTimeSeriesDataset(Dataset):
    def __init__(self, data, seq_length=10):
        self.seq_length = seq_length
        
        # Features: total_packets, malicious_packets, packet_rate, anomaly_score
        self.features = data[['total_packets', 'malicious_packets', 'packet_rate', 'anomaly_score']].values
        self.targets = data['attack_occurred'].values
        
        self.samples = []
        
        # Construct sliding windows
        # We need seq_length steps of past data
        # Target 1m is the target at t+1
        # Target 5m is if ANY attack occurs in t+1 to t+5
        # Target 15m is if ANY attack occurs in t+1 to t+15
        for i in range(len(data) - seq_length - 15):
            x = self.features[i : i + seq_length]
            
            # Targets lookahead
            y_1m = float(self.targets[i + seq_length])  # next step (1 minute)
            y_5m = float(np.any(self.targets[i + seq_length : i + seq_length + 5]))  # next 5 minutes
            y_15m = float(np.any(self.targets[i + seq_length : i + seq_length + 15]))  # next 15 minutes
            
            self.samples.append((
                torch.tensor(x, dtype=torch.float32),
                torch.tensor([y_1m, y_5m, y_15m], dtype=torch.float32)
            ))
            
    def __len__(self):
        return len(self.samples)
        
    def __getitem__(self, idx):
        return self.samples[idx]

# 2. LSTM Model Definition
class ThreatForecasterLSTM(nn.Module):
    def __init__(self, input_dim=4, hidden_dim=32, num_layers=2, output_dim=3):
        super(ThreatForecasterLSTM, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2 if num_layers > 1 else 0.0)
        self.fc = nn.Linear(hidden_dim, output_dim)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(x.device)
        
        out, _ = self.lstm(x, (h0, c0))
        # Take the output of the last sequence step
        out = out[:, -1, :]
        out = self.fc(out)
        out = self.sigmoid(out)
        return out

def train_forecaster():
    data_path = "ml_training/data/synthetic_time_series.csv"
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Please run generate_data.py first.")
        
    df = pd.read_csv(data_path)
    
    # Scale features
    feature_cols = ['total_packets', 'malicious_packets', 'packet_rate', 'anomaly_score']
    scaler = MinMaxScaler()
    df_scaled = df.copy()
    df_scaled[feature_cols] = scaler.fit_transform(df[feature_cols])
    
    seq_length = 10
    dataset = NetworkTimeSeriesDataset(df_scaled, seq_length=seq_length)
    
    # Split into train and validation
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
    
    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    
    # Init Model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = ThreatForecasterLSTM(input_dim=4, hidden_dim=32, num_layers=2, output_dim=3).to(device)
    
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)
    
    epochs = 15
    logger.info(f"Training ThreatForecasterLSTM model on device: {device}...")
    
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        for x_batch, y_batch in train_loader:
            x_batch, y_batch = x_batch.to(device), y_batch.to(device)
            
            optimizer.zero_grad()
            outputs = model(x_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item() * x_batch.size(0)
            
        train_loss /= len(train_loader.dataset)
        
        # Validation
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for x_batch, y_batch in val_loader:
                x_batch, y_batch = x_batch.to(device), y_batch.to(device)
                outputs = model(x_batch)
                loss = criterion(outputs, y_batch)
                val_loss += loss.item() * x_batch.size(0)
        val_loss /= len(val_loader.dataset)
        
        if (epoch + 1) % 3 == 0 or epoch == epochs - 1:
            logger.info(f"Epoch {epoch+1}/{epochs} - Train Loss: {train_loss:.4f} - Val Loss: {val_loss:.4f}")
            
    # Save Model weights and Scaler
    os.makedirs("ml_training/models", exist_ok=True)
    
    # Save weights
    torch.save(model.state_dict(), "ml_training/models/forecaster_lstm.pth")
    # Save scaling details
    joblib.dump(scaler, "ml_training/models/forecaster_scaler.joblib")
    
    logger.info("Threat forecasting model and scaler successfully saved.")
    
    # Validation preview
    model.eval()
    logger.info("Testing forecast predictions on sample validation sequences:")
    with torch.no_grad():
        x_sample, y_sample = next(iter(val_loader))
        x_sample = x_sample.to(device)
        preds = model(x_sample)
        
        for idx in range(min(5, len(x_sample))):
            pred_val = preds[idx].cpu().numpy()
            true_val = y_sample[idx].numpy()
            print(f"Sample {idx+1}: Predicted Probabilities -> [1m: {pred_val[0]*100:.1f}%, 5m: {pred_val[1]*100:.1f}%, 15m: {pred_val[2]*100:.1f}%] | "
                  f"True Labels -> [1m: {int(true_val[0])}, 5m: {int(true_val[1])}, 15m: {int(true_val[2])}]")

if __name__ == "__main__":
    train_forecaster()
