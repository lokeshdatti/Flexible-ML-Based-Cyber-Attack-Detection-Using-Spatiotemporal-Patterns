# RF-LSTM IDS - Real-Time Intrusion Detection Dashboard

A cybersecurity-themed web application for real-time network intrusion detection using Random Forest + LSTM hybrid model.

## Features

🛡️ **Real-Time Analysis**
- Process CSV network traffic data packet-by-packet
- Convert PCAP files to features and analyze
- Color-coded attack type visualization
- Animated grid display with confidence scores

🎯 **Attack Detection**
- Multi-class classification (BENIGN, DoS, DDoS, PortScan, etc.)
- Confidence scoring for each prediction
- Live threat log with timestamps
- Statistics dashboard

🎨 **Cybersecurity Theme**
- Terminal/hacker aesthetic with green matrix colors
- Animated background effects (scan lines, grid overlay)
- Glowing elements and hover effects
- Responsive design

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Place Model Files

Ensure these files are in the root directory:
- `rf_feature_extractor.pkl` - Random Forest model
- `rf_lstm_hybrid_model.h5` - LSTM model
- `scaler.pkl` - Feature scaler
- `label_encoder.pkl` - Label encoder

### 3. Run the Application

```bash
python app.py
```

The app will start on `http://localhost:5000`

## Usage

### Option 1: CSV Upload

1. Click **CSV Upload** card
2. Select or drag-drop a CSV file with network traffic features
3. Click **ANALYZE CSV** button
4. Watch real-time packet analysis with predictions

### Option 2: PCAP Upload

1. Click **PCAP Upload** card
2. Select or drag-drop a `.pcap` or `.pcapng` file
3. The system automatically converts packets to features
4. Click **ANALYZE PCAP** button
5. View real-time analysis

## Controls

- **PAUSE/RESUME** - Pause or resume the analysis
- **SPEED** - Adjust analysis speed (0.5x, 1x, 2x, 5x)

## CSV Format

Your CSV should contain network traffic features like:
- Flow Duration
- Total Fwd/Bwd Packets
- Packet Lengths
- Flow Bytes/s
- IAT (Inter-Arrival Time) features
- TCP Flags
- etc.

**Note:** Do NOT include a 'Label' column - the system will predict this.

## Attack Types & Colors

| Attack Type | Color |
|------------|-------|
| BENIGN | Green (#00ff41) |
| DoS | Red (#ff0000) |
| DDoS | Red (#ff3333) |
| PortScan | Orange (#ff6600) |
| Bot | Purple (#cc00ff) |
| Web Attack | Orange (#ffaa00) |
| Others | Red variants |

## Project Structure

```
.
├── app.py                 # Flask backend
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html        # Main HTML template
├── static/
│   ├── css/
│   │   └── style.css     # Cybersecurity-themed styles
│   └── js/
│       └── app.js        # Frontend logic
├── uploads/              # Temporary file storage
├── rf_feature_extractor.pkl
├── rf_lstm_hybrid_model.h5
├── scaler.pkl
└── label_encoder.pkl
```

## Technical Details

### Backend (Flask)
- File upload handling (CSV/PCAP)
- PCAP to feature conversion using Scapy
- RF+LSTM prediction pipeline
- RESTful API endpoints

### Frontend
- Vanilla JavaScript (no frameworks)
- Real-time WebSocket-style updates using AJAX
- CSS animations and transitions
- Responsive grid layout

### Models
- **Random Forest**: Feature extraction and probability generation
- **LSTM**: Sequential pattern learning on enhanced features
- **Hybrid Approach**: Combines RF probabilities with original features

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main page |
| `/upload_csv` | POST | Upload CSV file |
| `/upload_pcap` | POST | Upload PCAP file |
| `/predict_row` | POST | Get prediction for single row |
| `/get_stats` | POST | Get session statistics |

## Performance Tips

1. **Large Files**: Limit CSV to reasonable size (< 10k rows) for smooth UI
2. **PCAP Files**: Automatically limited to first 1000 packets
3. **Speed Control**: Use speed multiplier to adjust visualization pace
4. **Browser**: Chrome/Edge recommended for best performance

## Troubleshooting

### Models not loading
- Ensure all 4 model files are in the root directory
- Check file permissions

### PCAP conversion fails
- Install Scapy properly: `pip install scapy`
- Try with a smaller PCAP file first

### Slow predictions
- Reduce speed multiplier
- Process smaller batches

## Future Enhancements

- [ ] WebSocket for true real-time streaming
- [ ] Export analysis reports (PDF/CSV)
- [ ] Live network capture integration
- [ ] Multi-session support
- [ ] Attack type statistics charts
- [ ] Custom alert thresholds

## License

MIT License - Feel free to use and modify!

## Credits

Built with:
- Flask (Backend)
- TensorFlow/Keras (ML)
- Scapy (Packet analysis)
- Custom CSS animations (UI)
