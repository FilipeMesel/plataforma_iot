from flask import Flask
from flask import jsonify
from flask import request
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import create_access_token
from flask_jwt_extended import unset_jwt_cookies
from flask_jwt_extended import get_jwt_identity
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json


app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1800  # 30 minute
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Defina as classes de modelo para as entidades

users_empreendimentos = db.Table(
    'users_empreendimentos',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('empreendimento_id', db.Integer, db.ForeignKey('empreendimento.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    phone = db.Column(db.String(15))
    classe = db.Column(db.String(15))
    #empreendimentos = db.relationship('Empreendimento', secondary=users_empreendimentos, backref='users', lazy=True)
    #empreendimentos = db.relationship('Empreendimento', backref='user', lazy=True)
    empreendimentos = db.relationship('Empreendimento', secondary=users_empreendimentos, backref=db.backref('users', lazy=True))


class Empreendimento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50))
    cnpj = db.Column(db.String(14), unique=True)
    cidade = db.Column(db.String(50))
    estado = db.Column(db.String(2))
    rua = db.Column(db.String(50))
    numero = db.Column(db.String(10))
    ambientes = db.relationship('Ambiente', backref='empreendimento', lazy=True)

class Ambiente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50))
    empreendimento_id = db.Column(db.Integer, db.ForeignKey('empreendimento.id'), nullable=False)
    tipo = db.Column(db.String(50)) # Fazenda ou Outros
    devices = db.relationship('Device', backref='ambiente', lazy=True)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(50), unique=True)
    apelido = db.Column(db.String(50))
    tipo = db.Column(db.String(100))
    ambiente_id = db.Column(db.Integer, db.ForeignKey('ambiente.id'), nullable=False)
    dados = db.relationship('DadosDevice', backref='device', lazy=True)

class DadosDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    json_data = db.Column(db.String)
    timestamp=datetime.utcnow()

@app.route('/users/empreendimento/<int:empreendimento_id>', methods=['GET'])
def get_users_by_empreendimento(empreendimento_id):
    empreendimento = Empreendimento.query.get(empreendimento_id)
    if not empreendimento:
        return jsonify({'message': 'Empreendimento not found'}), 404

    users = empreendimento.users
    users_data = [{'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone} for user in users]
    return jsonify(users_data)

@app.route('/users/empreendimentos', methods=['POST'])
def add_empreendimento_to_user():
    data = request.json
    user_id = data.get('user_id')
    empreendimento_id = data.get('empreendimento_id')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    empreendimento = Empreendimento.query.get(empreendimento_id)
    if not empreendimento:
        return jsonify({'message': 'Empreendimento not found'}), 404

    user.empreendimentos.append(empreendimento)
    db.session.commit()

    return jsonify({'message': 'Empreendimento added to user successfully'})


@app.route('/empreendimentos/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_empreendimentos_by_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    empreendimentos = user.empreendimentos
    empreendimentos_data = [
        {
            'id': empreendimento.id,
            'nome': empreendimento.nome,
            'cnpj': empreendimento.cnpj,
            'cidade': empreendimento.cidade,
            'estado': empreendimento.estado,
            'rua': empreendimento.rua,
            'numero': empreendimento.numero
        }
        for empreendimento in empreendimentos
    ]
    return jsonify(empreendimentos_data)

# Rotas CRUD para Usuário
@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    users_data = [{'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone} for user in users]
    return jsonify(users_data)

@app.route('/users', methods=['POST'])
def create_user():
    data = request.json
    user = User(name=data['name'], email=data['email'], password=data['password'], phone=data['phone'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'})

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    user_data = {'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone}
    return jsonify(user_data)

@app.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    data = request.json
    user.name = data['name']
    user.email = data['email']
    user.password = data['password']
    user.phone = data['phone']
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

@app.route('/users/change_password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.json
    user_id = data.get('user_id')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user.password != old_password:
        return jsonify({'message': 'Invalid old password'}), 400

    user.password = new_password
    db.session.commit()

    return jsonify({'message': 'Password changed successfully'})

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

@app.route('/empreendimentos', methods=['GET'])
def get_empreendimentos():
    empreendimentos = Empreendimento.query.all()
    empreendimentos_data = [
        {
            'id': empreendimento.id,
            'nome': empreendimento.nome,
            'cnpj': empreendimento.cnpj,
            'cidade': empreendimento.cidade,
            'estado': empreendimento.estado,
            'rua': empreendimento.rua,
            'numero': empreendimento.numero
        }
        for empreendimento in empreendimentos
    ]
    return jsonify(empreendimentos_data)

@app.route('/empreendimentos', methods=['POST'])
def create_empreendimento():
    data = request.json
    empreendimento = Empreendimento(
        nome=data['nome'],
        cnpj=data['cnpj'],
        cidade=data['cidade'],
        estado=data['estado'],
        rua=data['rua'],
        numero=data['numero']
    )
    db.session.add(empreendimento)
    db.session.commit()
    return jsonify({'message': 'Empreendimento created successfully'})

@app.route('/empreendimentos/<int:empreendimento_id>', methods=['GET'])
@jwt_required()
def get_empreendimento(empreendimento_id):
    empreendimento = Empreendimento.query.get(empreendimento_id)
    if not empreendimento:
        return jsonify({'message': 'Empreendimento not found'}), 404
    empreendimento_data = {
        'id': empreendimento.id,
        'nome': empreendimento.nome,
        'cnpj': empreendimento.cnpj,
        'cidade': empreendimento.cidade,
        'estado': empreendimento.estado,
        'rua': empreendimento.rua,
        'numero': empreendimento.numero
    }
    return jsonify(empreendimento_data)

@app.route('/empreendimentos/<int:empreendimento_id>', methods=['PUT'])
def update_empreendimento(empreendimento_id):
    empreendimento = Empreendimento.query.get(empreendimento_id)
    if not empreendimento:
        return jsonify({'message': 'Empreendimento not found'}), 404
    data = request.json
    empreendimento.nome = data['nome']
    empreendimento.cnpj = data['cnpj']
    empreendimento.cidade = data['cidade']
    empreendimento.estado = data['estado']
    empreendimento.rua = data['rua']
    empreendimento.numero = data['numero']
    db.session.commit()
    return jsonify({'message': 'Empreendimento updated successfully'})

@app.route('/empreendimentos/<int:empreendimento_id>', methods=['DELETE'])
def delete_empreendimento(empreendimento_id):
    empreendimento = Empreendimento.query.get(empreendimento_id)
    if not empreendimento:
        return jsonify({'message': 'Empreendimento not found'}), 404
    db.session.delete(empreendimento)
    db.session.commit()
    return jsonify({'message': 'Empreendimento deleted successfully'})

@app.route('/ambientes', methods=['GET'])
def get_ambientes():
    ambientes = Ambiente.query.all()
    ambientes_data = [
        {
            'id': ambiente.id,
            'nome': ambiente.nome,
            'empreendimento_id': ambiente.empreendimento_id,
            'tipo': ambiente.tipo
        }
        for ambiente in ambientes
    ]
    return jsonify(ambientes_data)

@app.route('/ambientes', methods=['POST'])
# @jwt_required()
def create_ambiente():
    data = request.json
    ambiente = Ambiente(
        nome=data['nome'],
        empreendimento_id=data['empreendimento_id'],
        tipo=data['tipo']
    )
    print(ambiente.nome, ambiente.empreendimento_id, ambiente.tipo)
    db.session.add(ambiente)
    db.session.commit()
    return jsonify({'message': 'Ambiente created successfully'})



@app.route('/ambientes/empreendimento/<int:empreendimento_id>', methods=['GET'])
@jwt_required()
def get_ambiente(empreendimento_id):
    ambientes = Ambiente.query.filter_by(empreendimento_id=empreendimento_id).all()
    if not ambientes:
        return jsonify({'message': 'Ambientes not found'}), 404

    ambientes_data = [
        {
            'id': ambiente.id,
            'nome': ambiente.nome,
            'empreendimento_id': ambiente.empreendimento_id,
            'tipo': ambiente.tipo
        }
        for ambiente in ambientes
    ]
    
    return jsonify(ambientes_data)

@app.route('/ambientes/<int:amdiente_id>', methods=['GET'])
@jwt_required()
def get_ambiente_id(amdiente_id):
    ambientes = Ambiente.query.filter_by(id=amdiente_id).first()
    if not ambientes:
        return jsonify({'message': 'Ambientes not found'}), 404

    ambientes_data = {
            'id': ambientes.id,
            'nome': ambientes.nome,
            'empreendimento_id': ambientes.empreendimento_id,
            'tipo': ambientes.tipo
        }
    
    return jsonify(ambientes_data)

@app.route('/users/<int:user_id>/ambientes', methods=['GET'])
def get_ambientes_by_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    ambientes = Ambiente.query.filter(Ambiente.empreendimento_id.in_(empreendimento.id for empreendimento in user.empreendimentos)).all()
    ambientes_data = [
        {
            'id': ambiente.id,
            'nome': ambiente.nome,
            'empreendimento_id': ambiente.empreendimento_id,
            'tipo': ambiente.tipo
        }
        for ambiente in ambientes
    ]
    return jsonify(ambientes_data)

@app.route('/ambientes/<int:ambiente_id>', methods=['PUT'])
@jwt_required()
def update_ambiente(ambiente_id):
    ambiente = Ambiente.query.get(ambiente_id)
    if not ambiente:
        return jsonify({'message': 'Ambiente not found'}), 404
    data = request.json
    ambiente.nome = data['nome']
    ambiente.empreendimento_id = data['empreendimento_id']
    db.session.commit()
    return jsonify({'message': 'Ambiente updated successfully'})

@app.route('/ambientes/<int:ambiente_id>', methods=['DELETE'])
@jwt_required()
def delete_ambiente(ambiente_id):
    ambiente = Ambiente.query.get(ambiente_id)
    if not ambiente:
        return jsonify({'message': 'Ambiente not found'}), 404

    devices = Device.query.filter_by(ambiente_id=ambiente_id).all()
    if devices:
        return jsonify({'message': 'Cannot delete ambiente with associated devices'}), 400

    db.session.delete(ambiente)
    db.session.commit()
    return jsonify({'message': 'Ambiente deleted successfully'})

@app.route('/devices', methods=['GET'])
def get_devices():
    serial_number = request.args.get('serial_number')

    if serial_number:
        device = Device.query.filter_by(serial_number=serial_number).first()
        if not device:
            return jsonify({'message': 'Device not found'}), 404
        device_data = {
            'id': device.id,
            'serial_number': device.serial_number,
            'apelido': device.apelido,
            'ambiente_id': device.ambiente_id,
            'tipo': device.tipo
        }
        return jsonify(device_data)
    else:
        devices = Device.query.all()
        devices_data = [
            {
                'id': device.id,
                'serial_number': device.serial_number,
                'apelido': device.apelido,
                'ambiente_id': device.ambiente_id,
                'tipo': device.tipo
            }
            for device in devices
        ]
        return jsonify(devices_data)


@app.route('/devices', methods=['POST'])
@jwt_required()
def create_device():
    data = request.json
    device = Device(
        serial_number=data['serial_number'],
        apelido=data['apelido'],
        ambiente_id=data['ambiente_id'],
        tipo=data['tipo']
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({'message': 'Device created successfully'})

@app.route('/devices/<int:device_id>', methods=['GET'])
@jwt_required()
def get_device(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'message': 'Device not found'}), 404
    device_data = {
        'id': device.id,
        'serial_number': device.serial_number,
        'apelido': device.apelido,
        'ambiente_id': device.ambiente_id,
        'tipo': device.tipo
    }
    return jsonify(device_data)

@app.route('/devices/<int:ambiente_id>/ambiente', methods=['GET'])
@jwt_required()
def get_devices_by_ambiente(ambiente_id):
    ambiente = Ambiente.query.get(ambiente_id)
    if not ambiente:
        return jsonify({'message': 'Ambiente not found'}), 404

    devices = ambiente.devices
    devices_data = [
        {
            'id': device.id,
            'serial_number': device.serial_number,
            'apelido': device.apelido,
            'ambiente_id': device.ambiente_id,
            'tipo': device.tipo
        }
        for device in devices
    ]
    return jsonify(devices_data)

@app.route('/devices/<int:device_id>', methods=['PUT'])
@jwt_required()
def update_device(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'message': 'Device not found'}), 404
    data = request.json
    device.serial_number = data['serial_number']
    device.apelido = data['apelido']
    device.ambiente_id = data['ambiente_id']
    device.tipo = data['tipo']
    db.session.commit()
    return jsonify({'message': 'Device updated successfully'})

@app.route('/devices/<int:device_id>', methods=['DELETE'])
@jwt_required()
def delete_device(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'message': 'Device not found'}), 404
    db.session.delete(device)
    db.session.commit()
    dado = DadosDevice.query.get(device_id = device_id)
    if not dado:
        return jsonify({'message': 'Dado not found'}), 404
    db.session.delete(dado)
    db.session.commit()
    return jsonify({'message': 'Device deleted successfully'})

@app.route('/dados', methods=['GET'])
def get_dados():
    dados = DadosDevice.query.all()
    dados_data = [{'id': dado.id, 'json_data': dado.json_data} for dado in dados]
    return jsonify(dados_data)

@app.route('/dados', methods=['POST'])
def create_dado():
    data = request.json
    device = Device.query.filter_by(serial_number=data['serial_number']).first()
    if not device:
        return jsonify({'message': 'Device not found'}), 404
    
    json_data = json.dumps(data['json_data'])  # Converter o objeto JSON em uma string

    dado = DadosDevice(json_data=json_data)
    dado.device_id = device.id
    db.session.add(dado)
    db.session.commit()
    return jsonify({'message': 'Dado created successfully'})

# Retorna os dados de um serial_number específico
@app.route('/devices/serial/<string:serial_number>/dados', methods=['GET'])
def get_device__serial_dados(serial_number):
    device = Device.query.filter_by(serial_number=serial_number).first()
    if not device:
        return jsonify({'message': 'Device not found'}), 404

    dados = DadosDevice.query.filter_by(device_id=device.id).all()
    dados_data = [{'id': dado.id, 'json_data': dado.json_data} for dado in dados]
    return jsonify(dados_data)

# Retorna os dados de um serial_number específico
@app.route('/devices/id_device/<int:id_device>/dados', methods=['GET'])
def get_device_dados(id_device):
    device = Device.query.filter_by(id=id_device).first()
    if not device:
        return jsonify({'message': 'Device not found'}), 404

    dados = DadosDevice.query.filter_by(device_id=device.id).all()
    dados_data = [{'id': dado.id, 'json_data': dado.json_data} for dado in dados]
    return jsonify(dados_data)

@app.route('/dados/<int:dado_id>', methods=['GET'])
def get_dado(dado_id):
    dado = DadosDevice.query.get(dado_id)
    if not dado:
        return jsonify({'message': 'Dado not found'}), 404
    dado_data = {'id': dado.id, 'json_data': dado.json_data}
    return jsonify(dado_data)

@app.route('/dados/<int:dado_id>', methods=['PUT'])
def update_dado(dado_id):
    dado = DadosDevice.query.get(dado_id)
    if not dado:
        return jsonify({'message': 'Dado not found'}), 404
    data = request.json
    dado.json_data = data['json_data']
    db.session.commit()
    return jsonify({'message': 'Dado updated successfully'})


@app.route('/dados/<int:dado_id>', methods=['DELETE'])
def delete_dado(dado_id):
    dado = DadosDevice.query.get(dado_id)
    if not dado:
        return jsonify({'message': 'Dado not found'}), 404
    db.session.delete(dado)
    db.session.commit()
    return jsonify({'message': 'Dado deleted successfully'})

# Configurar o JWT
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    user_id = jwt_data["sub"]
    return User.query.get(user_id)

# Rota de login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Verifique se as credenciais são válidas
    user = User.query.filter_by(email=email).first()
    if user and user.password == password:
        # Gere um token de acesso
        access_token = create_access_token(identity=user)

        # Defina o token de acesso nos cookies de resposta
        # Obtenha o ID do usuário atualmente autenticado
        user_id = user.id
        response = jsonify({'message': 'Login successful', 'id': user_id, 'access_token': access_token})
        response.set_cookie('access_token', access_token, httponly=True)

        return response, 200

    return jsonify({'message': 'Invalid credentials'}), 401

# Rota de logout
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Remova o token de acesso dos cookies de resposta
    response = jsonify({'message': 'Logout successful'})
    print(response)
    unset_jwt_cookies(response)
    return response, 200

# Rotas protegidas por autenticação JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected_route():
    # Obtenha o ID do usuário atualmente autenticado
    user_id = get_jwt_identity()

    # Faça o que for necessário com o ID do usuário (por exemplo, recuperar dados do usuário)

    return jsonify({'message': 'Protected route', 'user_id': user_id}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
