from flask import Flask, render_template, request, redirect, jsonify, flash, url_for, send_from_directory
from werkzeug.utils import secure_filename
import os
import webbrowser
from RC5C import RC5C

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
HOST = ""
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

rc5 = 0
currentFile = ''

@app.route('/')
def index():
    global HOST
    HOST = request.host_url
    return render_template('index.html')


@app.route('/key', methods=['POST'])
def key():
    global rc5
    key = request.form['key'].encode()
    w = int(request.form['w'])
    r = int(request.form['r'])
    rc5 = RC5C(key, w, r)
    return jsonify({"code": 0, "key": str(rc5.key)})


@app.route('/encrypt', methods=['POST'])
def encrypt():
    global rc5
    try:
        text = request.form.get('text')
        
        encryptText = rc5.encrypt(text.encode('utf-8'))

        string = ""

        t = [text[i:i+rc5.blockSize*2] for i in range(0, len(text), rc5.blockSize*2)]
        for i, j in zip(t, encryptText):
            if len(i) < (rc5.blockSize*2):
                i += " "*(rc5.blockSize*2 - len(i))
            string += ">> {}\t--> {}\n".format(i, j.hex())
        string += ">>\n>> encrypt: {}\n".format(b''.join(encryptText).hex())
        return jsonify({"code": 0, "data": string, "encryptCode": b''.join(encryptText).hex() })
    except:
        return jsonify({"code": 1, "data": ">> Please assign key before encrypting\n"})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    global rc5
    try:
        text = request.form.get('text')
        
        decryptText = rc5.decrypt(bytes.fromhex(text))
        utf8String = str(b''.join(decryptText), 'utf-8')
        string = ""
        b = [text[i:i+rc5.blockSize*4] for i in range(0, len(text), rc5.blockSize*2)]
        t = [utf8String[i:i+rc5.blockSize*2] for i in range(0,len(utf8String),rc5.blockSize*2)]
        for i, j in zip(b, t):
            if len(i) < (rc5.blockSize*2):
                i += " "*(rc5.blockSize*2 - len(i))
            string += ">> {}\t--> {}\n".format(i, j)
        string += ">>\n>> decrypt: {}\n".format(utf8String)
        return jsonify({"code": 0, "data": string})
    except:
        return jsonify({"code": 1, "data": ">> Please enter hex string\n", "decryptCode": utf8String})


@app.route('/readFile', methods=['POST'])
def readFile():
    global currentFile
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            currentFile = "./{}".format(url_for('uploaded_file', filename=filename))
            with open(currentFile,'rb') as input:
                return jsonify({"code": 0, "data": ">> File content with hex: {}\n>> Go to {}{} to view\n".format(input.read(-1).hex(), HOST,format(url_for('uploaded_file', filename=filename)))})
            

    return 

@app.route('/encryptFile', methods=['POST'])
def encryptFile():
    global currentFile
    path = currentFile.rsplit('.', 1)[1].lower()

    outputPath = 'uploads/out.{}'.format(path)
    try:
        with open(currentFile,'rb') as input, open("./{}".format(outputPath),'wb') as output:
            text, encryptOut = encryptFile(input, output)
            currentFile = "./{}".format(outputPath)
            return jsonify({"code": 0, "data": ">> File encrypt: {}\n>> Go to {}{} to view\n".format(b''.join(encryptOut).hex(),HOST,outputPath), "url": "{}{}".format(HOST,outputPath)})
    except:
        return jsonify({"code": 1, "data": ">> Please assign key before encrypting\n"})

@app.route('/decryptFile', methods=['POST'])
def decryptFile():
    global currentFile
    path = currentFile.rsplit('.', 1)[1].lower()
    outputPath = 'uploads/decrypt.{}'.format(path)
    try:
        with open(currentFile,'rb') as input, open('./{}'.format(outputPath),'wb') as output:
            text, decryptOut = decryptFile(input, output)
            return jsonify({"code": 0, "data": ">> File decrypt: {}\n>> Go to {}{} to view\n".format(b''.join(decryptOut).hex(),HOST, outputPath), "url": "{}{}".format(HOST,outputPath)})
    except:
        return jsonify({"code": 1, "data": ">> Please assign key before decrypting\n"})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

def encryptFile(input, output):
    global rc5
    print(rc5)
    text = input.read(-1)
    encryptOut = rc5.encrypt(text)
    output.write(b''.join(encryptOut))
    return text, encryptOut

def decryptFile(input, output):
    global rc5
    text = input.read(-1)
    decryptOut = rc5.decrypt(text)
    output.write(b''.join(decryptOut))
    return text, decryptOut

if __name__ == "__main__":
    app.run(debug=True)