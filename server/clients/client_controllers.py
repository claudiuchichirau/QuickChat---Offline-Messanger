from flask import jsonify, request
from sqlalchemy.exc import IntegrityError
from server.server import db

def create_user():
    data = request.get_json()

    new_user = User(username=data['username'], password=data['password'])

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username already exists'}), 400