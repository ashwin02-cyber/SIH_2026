import sys
import json
sys.stdout.reconfigure(encoding='utf-8')
from predict import predict_from_pcap

result = predict_from_pcap('web_sample.pcap')
print(json.dumps(result, indent=2, default=str))