import torch
import sys
import joblib
import numpy as np
import torch.nn as nn
from config import (MODEL_PATH, SCALER_PATH,
                    FEATURE_COLS_PATH, LABEL_ENCODER_PATH)

# ═══════════════════════════════════════════════════════════════
#  4. DL MODEL
# ═══════════════════════════════════════════════════════════════
class SimpleMLP(nn.Module):
    def __init__(self, input_dim: int, num_classes: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 128), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(128, 64),        nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )


# ! find this forward and also find where is backward
    def forward(self, x):
        return self.network(x)


def load_dl_system():
    try:
        scaler       = joblib.load(SCALER_PATH) # load all data - math 
        le           = joblib.load(LABEL_ENCODER_PATH) # it give us labels 0 = Normal and 1 = DoS
        feature_cols = joblib.load(FEATURE_COLS_PATH) # list of features on which our model is trains 
        device       = torch.device("cuda" if torch.cuda.is_available() else "cpu") # i dont have cudo -> nvdia gpu 
        model        = SimpleMLP(len(feature_cols), len(le.classes_)).to(device) # empty version of the SimpleMLP
        

#A "State Dict" is just a big dictionary (list) of all the Weights and Biases the AI learned during training.
#This line takes those learned numbers and "plugs" them into the neurons of your SimpleMLP model.
        model.load_state_dict( 
            torch.load(MODEL_PATH,
                        map_location=device, # use my device 
                          weights_only=True #secuirty check that in file there will be just weights not any malicious script 

                          )
        )
        model.eval() # after traning it give us best model 

        print(f"  DL model loaded  : {len(feature_cols)} features, "
              f"classes={list(le.classes_)}, device={device}")
        return model, scaler, le, feature_cols, device
    except Exception as e:
        print(f"[!] DL model loading failed: {e}")
        sys.exit(1)

MODEL, SCALER, LE, FEATURE_COLS, DEVICE = load_dl_system()




def dl_classify(features: dict):

    # getting the value of features in the order of feature cols and if any feature is missing we will fill it with 0
    arr = np.array(
        [[features.get(col, 0) for col in FEATURE_COLS]], dtype=np.float32
    )

    # if any value is nan or inf, replace with 0 (to avoid model errors)
    arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

    # scale features to same range as training data (important for model performance)
    arr = SCALER.transform(arr)



 # convert to PyTorch tensor bcz it not  work with np and move to same device as model (cpu)  
    t = torch.tensor(arr, dtype=torch.float32).to(DEVICE)

    with torch.no_grad(): # not calculate gradients
        logits = MODEL(t) # forward pass through the neural network to get raw output scores 
        if torch.isnan(logits).any():  # if any value in logits is NaN, return normal with 0 confidence to avoid crashing
            return "Normal Traffic", 0.0
        probs      = torch.softmax(logits, dim=1) # convert logits to probabilities 

        conf, idx  = torch.max(probs, 1) # get the highest probability and its corresponding class index like this -> 
        #conf = 0.93      ← confidence score
        # idx  = 2         ← index of winning class

    label = LE.inverse_transform([idx.item()])[0] # convert class index back to original label string using the label encoder

# returining the tuple : label            
#   # a string  →  "Port Scanning"
# round(conf.item(), 4)   →  0.9312
    return label, round(conf.item(), 4)    