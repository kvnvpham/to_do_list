from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from forms import ToDoForm, RegisterForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
Bootstrap(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    to_dos = relationship("ToDoList", back_populates="author")
    completed_to_dos = relationship("CompletedTasks", back_populates="author")


class ToDoList(db.Model):
    __tablename__ = "to_do"
    id = db.Column(db.Integer, primary_key=True)
    to_do = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="to_dos")


class CompletedTasks(db.Model):
    __tablename__ = "completed"
    id = db.Column(db.Integer, primary_key=True)
    completed_task = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="completed_to_dos")


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def welcome():
    return render_template("index.html")


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("That User Already Exists, Please Login Instead")
            return redirect(url_for("login"))

        secure_pw = generate_password_hash(
            form.password.data,
            method="pbkdf2:sha256",
            salt_length=8
        )

        new_user = User(
            name=form.name.data,
            username=form.username.data,
            password=secure_pw,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home", user_id=current_user.id))

    return render_template("register.html", form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash("Please Enter A Valid User Name.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, form.password.data):
            flash("Incorrect Password, Please Try Again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("home", user_id=current_user.id))

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("welcome"))


@app.route("/home/<int:user_id>", methods=['GET', 'POST'])
@login_required
def home(user_id):
    if user_id == current_user.id:
        form = ToDoForm()

        if form.validate_on_submit():
            user = User.query.get(user_id)
            item = ToDoList(to_do=form.to_do.data,
                            author=user
                            )
            db.session.add(item)
            db.session.commit()

            return redirect(url_for("get_all_tasks", user_id=current_user.id))

        return render_template("home.html", form=form)
    else:
        return abort(403)


@app.route("/tasks/<int:user_id>", methods=['GET', 'POST'])
@login_required
def get_all_tasks(user_id):
    if user_id == current_user.id:
        all_user_tasks = User.query.get(user_id)
        form = ToDoForm()

        if form.validate_on_submit():
            add_task = ToDoList(to_do=form.to_do.data,
                                author=all_user_tasks
                                )
            db.session.add(add_task)
            db.session.commit()
            return redirect(url_for("get_all_tasks", user_id=current_user.id))

        return render_template("todo.html",
                               form=form,
                               all_tasks=all_user_tasks,
                               user_id=current_user.id
                               )
    else:
        return abort(403)


@app.route("/finished-task/<int:user_id>/<int:task_id>/")
@login_required
def mark_check(user_id, task_id):
    if user_id == current_user.id:
        user = User.query.get(user_id)

        mark_task = ToDoList.query.get(task_id)
        finished = CompletedTasks(completed_task=mark_task.to_do,
                                  author=user
                                  )
        db.session.add(finished)
        db.session.delete(mark_task)
        db.session.commit()

        return redirect(url_for("get_all_tasks", user_id=current_user.id))
    else:
        return abort(403)


@app.route("/uncheck/<int:user_id>/<int:item_id>")
@login_required
def mark_uncheck(user_id, item_id):
    if user_id == current_user.id:
        user = User.query.get(user_id)

        uncheck = CompletedTasks.query.get(item_id)
        not_finished = ToDoList(to_do=uncheck.completed_task,
                                author=user
                                )
        db.session.add(not_finished)
        db.session.delete(uncheck)
        db.session.commit()
        return redirect(url_for("get_all_tasks", user_id=current_user.id))
    else:
        return abort(403)


@app.route("/clear/<int:user_id>/<int:item_id>")
@login_required
def clear_task(user_id, item_id):
    if user_id == current_user.id:
        item = CompletedTasks.query.get(item_id)

        db.session.delete(item)
        db.session.commit()
        return redirect(url_for("get_all_tasks", user_id=current_user.id))
    else:
        return abort(403)


@app.context_processor
def inject_copyright():
    return {"year": date.today().year}


if __name__ == "__main__":
    app.run()
