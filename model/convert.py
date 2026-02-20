"""
convert.py — Convert trained sklearn ensemble to ONNX (48 features)
Run this if you train the model externally and have a .pkl file.
For end-to-end training+export, prefer train.py instead.
"""
import pickle, numpy as np
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as rt

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

initial_type = [("input", FloatTensorType([None, 48]))]
onnx_model = convert_sklearn(model, initial_types=initial_type,
                              options={"zipmap": False}, target_opset=17)
with open("model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

sess = rt.InferenceSession("model.onnx")
dummy = np.random.rand(1, 48).astype(np.float32)
out = sess.run(None, {"input": dummy})
print(f"Converted. Output names: {[o.name for o in sess.get_outputs()]}")
print(f"Sample output: {out}")
