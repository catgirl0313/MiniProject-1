from pymongo import MongoClient
import jwt
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup

import certifi

from pymongo import MongoClient
client = MongoClient('mongodb+srv://test:sparta@cluster0.8vjpv.mongodb.net/?retryWrites=true&w=majority',tlsCAFile=certifi.where())
db = client.dbsparta

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['UPLOAD_FOLDER'] = "./static/profile_pics"

SECRET_KEY = 'SPARTA'

@app.route('/')
def home():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({"username": payload["id"]})
        cards = list(db.ASMR.find({}, {"_id": False}))
        return render_template('index.html', user_info=user_info, cards=cards)
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))


@app.route('/login')
def login():
    msg = request.args.get("msg")
    return render_template('login.html', msg=msg)


@app.route('/user/<username>')
def user(username):
    # 각 사용자의 프로필과 글을 모아볼 수 있는 공간
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        status = (username == payload["id"])  # 내 프로필이면 True, 다른 사람 프로필 페이지면 False

        user_info = db.users.find_one({"username": username}, {"_id": False})
        return render_template('user.html', user_info=user_info, status=status)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))

# 로그인 서버
# 서버에서는 로그인에서 검증요청을 보낸 아이디, 비밀번호 값을 가지고
# 실제 db에 이 아이디와 패스워드를 가진 유저가 실제로 존재하는지 판단.
# 아이디는 그대로 쓰고 패스워드는 로그인에서 sha456 해시함수로 암호화 했기때문에
# 여기서도 암호화를 진행해야된다.

# ------ 전체적인 정리 ------
# 클라이언트는 아이디와 비밀번호를 받아서 서버한테 검증을 요청하고
# 서버는 아이디와 비밀번호를 db로 찾아봐서 매칭되면 로그인이 성공했다는 사실을 jwt토큰을 발행해서 클라이언트에게 던져주게 됨.
# 클라이언트는 jwt토큰을 받으면 쿠키에 유요할때까지(내가 설정한 24시간동안) 계속 쓰이게된다.
# 그래서 jwt토큰은 놀이공원에서 자유입장권 같은 것이라고 한것임.

@app.route('/sign_in', methods=['POST'])
def sign_in():
    # 로그인에서 아이디와 비밀번호를 받는다.
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']

    # 로그인쪽과 같이 해시함수를 이용해서 암호화한다.
    pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    # 그래서 이 아이디와 비밀번호가 매칭되는 사람이 있는지 판단을 한다.
    # 만약에 매칭되는 사람이 있다면 로그인성공!
    # 매칭되는 사람이 없다면 둘중 하나 잘못입력한것
    result = db.users.find_one({'username': username_receive, 'password': pw_hash})

    if result is not None:
        # 로그인 성공한 경우
        # 아이디와 비밀번호를 제대로 설정했다면 서버에서 jwt토큰을 만들어서 발행한다.
        # jwt토큰은 놀이공원에서 자유입장권 같은것. '어떤사람이 언제까지 입장이 유효하다'라는 사실을 적시해준다.
        payload = {
         'id': username_receive,
         # 여기가 로그인 유효시간 정해주는곳.
         # datetime.utcnow() :지금부터 + timedelta(seconds=60 * 60 * 24) 최대 24시간까지
         'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
        }
        # payload로 jwt토큰을 만들어서 SECRET_KEY로 암호화를 만들어주고
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256') #.decode('utf-8') 왜 이걸 뒤에 붙이면 오류가 나지...?? 저거 없애니까 로그인 성공함..(코드스니펫 코드임)
        # 클라이언트에게('token': token) 넘겨주면 끝!
        return jsonify({'result': 'success', 'token': token})
    # 로그인 실패한 경우
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})

# 아이디는 그대로 저장하고 패스워드는 sha256이라는 해시함수를 써서 암호화해서 저장
@app.route('/sign_up/save', methods=['POST'])
def sign_up():
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']
    password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    doc = {
        "username": username_receive,                               # 아이디
        "password": password_hash,                                  # 비밀번호
        "profile_name": username_receive,                           # 프로필 이름 기본값은 아이디
        "profile_pic": "",                                          # 프로필 사진 파일 이름
        "profile_pic_real": "profile_pics/profile_placeholder.png", # 프로필 사진 기본 이미지
        "profile_info": ""                                          # 프로필 한 마디
    }
    db.users.insert_one(doc)
    return jsonify({'result': 'success'})

# *** 아이디 중복검사 ***
# 이미 클라이언트에서 빈값이나 형식에 맞지않는 건 걸러주어서
# 서버로 넘어오는 값은 이 두개를 통과한 값이다.
# 그래서 여기서는 이 username이 있는지 없는지만 체크해주면 됨.
@app.route('/sign_up/check_dup', methods=['POST'])
def check_dup():
    # request.form으로 username_give'을 받아서
    username_receive = request.form['username_give']
    # db.users.find_one으로 username이 뭐 하나라도 find 된다면
    # exists -> 존재하는 것
    # 만약에 db.users.find_one으로 username이 하나도 find 안된다면
    # bool -> 존재하지 않는것으로 인식됨.
    exists = bool(db.users.find_one({"username": username_receive}))
    # 그래서 이렇게 존재하는 것으로 login에 왔을때 response['exists']로 받으면
    # 이미 존재하는 아이디 입니다 라고 뜨게됨. -여기까지 id 중복검사
    return jsonify({'result': 'success', 'exists': exists})


#프로필 업데이트
#실제적인 이미지는 static파일에 들어가게 되고 db에는 이미지경로만 저장하게 된다.
@app.route('/update_profile', methods=['POST'])
def save_img():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        username = payload["id"]
        name_receive = request.form["name_give"]
        about_receive = request.form["about_give"]
        new_doc = {
            "profile_name": name_receive,
            "profile_info": about_receive
        }
        if 'file_give' in request.files:
            file = request.files["file_give"]
            filename = secure_filename(file.filename)
            extension = filename.split(".")[-1]
            file_path = f"profile_pics/{username}.{extension}"
            file.save("./static/" + file_path)
            new_doc["profile_pic"] = filename
            new_doc["profile_pic_real"] = file_path
        db.users.update_one({'username': payload['id']}, {'$set': new_doc})
        return jsonify({"result": "success", 'msg': '프로필을 업데이트했습니다.'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))


@app.route('/posting', methods=['POST'])
def posting():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({"username": payload["id"]})
        comment_receive = request.form["comment_give"]
        date_receive = request.form["date_give"]
        doc = {
            "username": user_info["username"],
            "profile_name": user_info["profile_name"],
            "profile_pic_real": user_info["profile_pic_real"],
            "comment": comment_receive,
            "date": date_receive
        }
        db.posts.insert_one(doc)
        return jsonify({"result": "success", 'msg': '포스팅 성공'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))

# 포스트는 가장 최근에 작성된것부터 가져오며, 최대20개까지 가져온다.
# 실제로 해당 포스트에 좋아요를 눌렀는지 누르지않았는지 확인하려면 각 포스트마다 고유 식별자가 필요하다 여기선 그것이 "_id"이다
# "_id"는 타입이 _id이므로 str로 변환해주는 작업이 필요하다.
# 그 후 클라이언트트 posts를 넘겨준다.
@app.route('/get_posts', methods=['GET'])
def get_posts():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        posts = list(db.posts.find({}).sort("date", -1).limit(20))
        for post in posts:
            post["_id"] = str(post["_id"])
        print(posts)
        return jsonify({"result": "success", "msg": "포스팅을 가져왔습니다.", "posts":posts})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))


@app.route('/update_like', methods=['POST'])
def update_like():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        # 좋아요 수 변경
        return jsonify({"result": "success", 'msg': 'updated'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))


@app.route('/main')
def main():
    cards = list(db.ASMR.find({}, {"_id": False}))
    print(cards)
    return render_template('index.html', cards=cards)

@app.route("/main/asmr", methods=["POST"])
def asmr_post():
    url_receive = request.form['url_give']
    category_receive = request.form['category_give']
    comment_receive = request.form['comment_give']

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'}
    data = requests.get(url_receive, headers=headers)

    soup = BeautifulSoup(data.text, 'html.parser')

    title = soup.select_one('meta[itemprop="name"][content]')['content']
    content = soup.select_one('meta[itemprop="description"][content]')['content']
    thumbnail = soup.select_one('link[itemprop="thumbnailUrl"][href]')['href']

    doc = {
        'title':title,
        'content':content,
        'thumbnail':thumbnail,
        'category':category_receive,
        'comment':comment_receive,
        'url':url_receive
    }
    db.ASMR.insert_one(doc)

    return jsonify({'msg':'저장 완료!'})

@app.route("/main/asmr/calm", methods=["GET"])
def asmr_get_1():
    ASMR_list = list(db.ASMR.find({'category':"1"}, {'_id': False}))
    return jsonify({'ASMRs':ASMR_list})


@app.route("/main/asmr/sleep", methods=["GET"])
def asmr_get_2():
    ASMR_list = list(db.ASMR.find({'category':"2"}, {'_id': False}))
    return jsonify({'ASMRs':ASMR_list})


@app.route("/main/asmr/concentration", methods=["GET"])
def asmr_get_3():
    ASMR_list = list(db.ASMR.find({'category':"3"}, {'_id': False}))
    return jsonify({'ASMRs':ASMR_list})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)