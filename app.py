from flask import Flask, redirect, url_for, render_template, request, session
from password_strength_analysis import evaluate_password_strength, hash_password_sha256, hash_password_bcrypt, test_password, check_uniqueness, check_complexity, check_pattern 


app = Flask(__name__)
app.secret_key = "hello"


@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "POST":
        passw = request.form["pw"]

        session["results"] = passw
        return redirect(url_for("results"))
    else:
        if "results" in session:
            return redirect(url_for("results"))
        return render_template("index.html")



@app.route("/results", methods=["POST", "GET"])
def results():
    if "results" in session:
        passw = session["results"]
        uniqueness_score = check_uniqueness(passw)
        complexity_score = check_complexity(passw)
        pattern_score = check_pattern(passw)
        password_str = evaluate_password_strength(passw)
        sha_r = hash_password_sha256(passw)
        bcrypt_r = hash_password_bcrypt(passw)
        tests = test_password(passw)
        data = [("uniqueness score", uniqueness_score), ("complexity score", complexity_score), ("pattern score", pattern_score)]
        labels = [row[0] for row in data]
        values = [row[1] for row in data]
        return render_template("analysis.html", pswd = passw, sha_result = sha_r, bcrypt_result = bcrypt_r, u_s = uniqueness_score, c_s = complexity_score, p_s = pattern_score, evaluate = password_str, labels=labels, values=values, condition=tests)
    else:
        return redirect(url_for("home"))
    if request.method == "POST":
        return redirect(url_for("home"))
    else:
        return render_template("analysis.html", pswd = passw, sha_result = sha_r, bcrypt_result = bcrypt_r, u_s = uniqueness_score, c_s = complexity_score, p_s = pattern_score, evaluate = password_str, labels=labels, values=values, condition=tests)


    

@app.route("/clear", methods=["POST", "GET"])
def clear():
    session.pop("results", None)
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)