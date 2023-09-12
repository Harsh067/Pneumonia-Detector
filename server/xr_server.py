from flask import Flask, request,jsonify
from tensorflow.keras.models import load_model
from keras import backend as K
from tensorflow.keras import backend as p
import json
from tensorflow.keras.preprocessing.image import  load_img, img_to_array
import os , io ,base64
import numpy as np
import json
from PIL import Image
app=Flask(__name__)

@app.route("/",methods=['POST'])
def server():
	data=request.get_json(force=True)
	data=data['img']

	f = io.BytesIO(base64.b64decode(data))
	img = Image.open(f)
	img = img.convert('RGB')
	img = img.resize((150, 150), Image.NEAREST)
	pilimage = np.asarray(img)
	img_t = np.expand_dims(pilimage, axis=0)

	p.clear_session()
	K.clear_session()
	r_model = load_model("xr_model_3.h5")
	res = r_model.predict(img_t)
	if res[0][0] == 1:
	    res = "You are Infected - Need to see doctor"
	else:
	    res = "Your Result is Normal :)"
	return jsonify(res)

if __name__=="__main__":
    app.run(debug="True")
