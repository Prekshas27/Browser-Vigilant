import pickle
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

with open("random_forest.pkl", "rb") as f:
    model = pickle.load(f)

initial_type = [("input", FloatTensorType([None, 30]))]

onnx_model = convert_sklearn(model, initial_types=initial_type)

with open("model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("Successfully converted random_forest.pkl to model.onnx")
