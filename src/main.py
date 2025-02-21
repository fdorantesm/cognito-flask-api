import time
import os
import re
from flask import Blueprint, Flask, json, make_response, request, jsonify
from dotenv import load_dotenv
from domain.password import Password
from vendors.cognito import client, hash
from flask_cors import CORS
from domain.user import User  # new import


env = os.path.join(os.getcwd(), '.env')

if os.path.exists(env):
    load_dotenv(dotenv_path=env)
else:
    load_dotenv()
    
DEBUG = os.getenv('DEBUG') == 'true' or False
CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')

app = Flask(__name__)
CORS(app)
port = os.getenv('PORT') or 8080

api = Blueprint('api', __name__, url_prefix='/api')

@api.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    try:
        response = client.initiate_auth(
            ClientId=os.getenv('COGNITO_CLIENT_ID'),
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': hash(username, CLIENT_ID, CLIENT_SECRET)
            }
        )
        
        if 'ChallengeName' in response:
            return jsonify({
                'data': {
                    'session': response['Session'],
                    'challenge': response['ChallengeName'],
                }
            })
        
        return jsonify({
            'message': 'Authentication successful',
            'data': {
                'accessToken': response['AuthenticationResult']['AccessToken'],
                'refreshToken': response['AuthenticationResult']['RefreshToken'],
                'idToken': response['AuthenticationResult']['IdToken'],
                'expiresIn': response['AuthenticationResult']['ExpiresIn'],
            }
        })
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({
            'message': 'Invalid username or password'
        }), 401)
        
@api.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']

    tacs = {
        'payments': False,
    }

    attributes = [
        {'Name': 'email', 'Value': username},
        {'Name': 'custom:tacs', 'Value': json.dumps(tacs)}
    ]
    
    if 'phone' in data:
        attributes.append({'Name': 'phone_number', 'Value': data["phone"]})
    
    try:
        response = client.admin_create_user(
            UserPoolId=os.getenv('COGNITO_POOL_ID'),
            Username=username,
            UserAttributes=attributes,
            # TemporaryPassword=Password.generate(8)
        )
        
        return jsonify({
            'message': 'User created. Password change required on first login.',
        })
    except client.exceptions.UsernameExistsException as e:
        print(e)
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 409)

@api.route('/auth/challenge', methods=['POST'])
def challenge():
    try:
        data = request.get_json()
        username = data['username']
        value = data['value']
        session = data['session']
        challenge = data['challenge']
        
        challenge_responses = {
            'USERNAME': username,
            'SECRET_HASH': hash(username, CLIENT_ID, CLIENT_SECRET)
        }
        
        # Obtener información del usuario para extraer phone_number
        user = client.admin_get_user(
            UserPoolId=os.getenv('COGNITO_POOL_ID'),
            Username=username
        )

        phone_number = next((attr['Value'] for attr in user.get('Attributes', []) if attr.get('Name') == 'phone_number'), None)

        if phone_number:
            print("phone_number:", phone_number)
        else:
            print("phone_number not found")
        
        if challenge == 'SMS_MFA':
            challenge_responses['SMS_MFA_CODE'] = value
        elif challenge == 'SOFTWARE_TOKEN_MFA':
            challenge_responses['SOFTWARE_TOKEN_MFA_CODE'] = value
        elif challenge == 'NEW_PASSWORD_REQUIRED':
            challenge_responses['NEW_PASSWORD'] = value
        elif challenge == 'EMAIL_OTP':
            challenge_responses['EMAIL_OTP_CODE'] = value
        
        response = client.respond_to_auth_challenge(
            ClientId=os.getenv('COGNITO_CLIENT_ID'),
            ChallengeName=challenge,
            Session=session,
            ChallengeResponses=challenge_responses
        )
        
        if response.get('AuthenticationResult'):
            return jsonify({
                'data': {
                    'accessToken': response['AuthenticationResult']['AccessToken'],
                    'refreshToken': response['AuthenticationResult']['RefreshToken'],
                    'idToken': response['AuthenticationResult']['IdToken'],
                    'expiresIn': response['AuthenticationResult']['ExpiresIn']
                }
            })
        elif response.get('ChallengeName'):
            return jsonify({
                'data': {
                    'session': response.get('Session'),
                    'challenge': response.get('ChallengeName')
                }
            })
        else:
            return make_response(jsonify({'message': 'Challenge not supported'}), 409)
            
    except Exception as e:
        return make_response(jsonify({'message': str(e)}), 400)   

@api.route('/auth/me', methods=['GET'])
def me():
    auth_header = request.headers.get('Authorization')
    token = re.match(r'Bearer (.*)', auth_header)[1] if auth_header else None
    
    if not token:
        return make_response(jsonify({'message': 'Invalid token'}), 401)
    
    try:
        response = client.get_user(AccessToken=token)
        attributes_list = response['UserAttributes']
        
        print(json.dumps(attributes_list, indent=2))
        
        user = User.fromAttributes(attributes_list)
        
        userdata = user.to_dict()
        
        return jsonify({'data': userdata})
    
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({'message': 'Invalid token'}), 401)

@api.route('/auth/send-password-recovery-link', methods=['POST'])
def send_password_recovery_link():
    data = request.get_json()
    username = data['username']
    
    try:
        client.forgot_password(
            ClientId=os.getenv('COGNITO_CLIENT_ID'),
            Username=username,
            SecretHash=hash(username, CLIENT_ID, CLIENT_SECRET),
        )
                                
        return jsonify({
            'message': 'Password recovery link sent'
        })
    except client.exceptions.UserNotFoundException as e:
        return make_response(jsonify({
            'message': 'User not found'
        }), 404)
    except client.exceptions.InvalidParameterException as e:
        print(e)
        return make_response(jsonify({
            'message': 'Invalid username'
        }), 400)
    except client.exceptions.LimitExceededException as e:
        return make_response(jsonify({
            'message': 'Limit exceeded'
        }), 429)
    except Exception as e:
        return make_response(jsonify({
            'message': str(e)
        }), 500)
    
@api.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data['username']
    password = data['password']
    code = data['code']
    
    try:
        client.confirm_forgot_password(
            ClientId=os.getenv('COGNITO_CLIENT_ID'),
            Username=username,
            ConfirmationCode=code,
            Password=password,
            SecretHash=hash(username, CLIENT_ID, CLIENT_SECRET),
        )
        
        return jsonify({
            'message': 'Password changed'
        })
    
    except client.exceptions.CodeMismatchException as e:
        return make_response(jsonify({
            'message': 'Invalid code'
        }), 400)
    except client.exceptions.ExpiredCodeException as e:
        return make_response(jsonify({
            'message': 'Expired code'
        }), 400)
    except client.exceptions.UserNotFoundException as e:
        return make_response(jsonify({
            'message': 'User not found'
        }), 404)
    except Exception as e:
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 500)
    
@api.route('/auth/password', methods=['POST'])
def password():
    data = request.get_json()
    password = data['password']
    auth_header = request.headers.get('Authorization')
    token = re.match(r'Bearer (.*)', auth_header)[1] if auth_header else None
    
    if not token:
        return make_response(jsonify({
            'message': 'Invalid token'
        }), 401)
        
    try:
        client.change_password(
            PreviousPassword=password,
            ProposedPassword=password,
            AccessToken=token
        )
                
        return jsonify({
            'message': 'Password changed'
        })
        
    except client.exceptions.LimitExceededException as e:
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 429)
        
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 401)
        
@api.route('/auth/privacy-policy', methods=['POST'])
def privacy_policy():
    
    auth_header = request.headers.get('Authorization')
    token = re.match(r'Bearer (.*)', auth_header)[1] if auth_header else None
    
    if not token:
        return make_response(jsonify({
            'message': 'Invalid token'
        }), 401)
    
    user = client.get_user(AccessToken=token)
    
    tacs = json.loads(next(attr['Value'] for attr in user['UserAttributes'] if attr['Name'] == 'custom:tacs'))
    tacs['payments'] = True
            
    try:
        client.update_user_attributes(
            AccessToken=token,
            UserAttributes=[
                {
                    'Name': 'custom:tacs',
                    'Value': json.dumps(tacs)
                }
            ]
        )
        
        return jsonify({
            'message': 'Privacy policy accepted'
        })
        
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 401)

@app.route('/info', methods=['GET'])
def info():
    try:
        response = client.describe_user_pool(
            UserPoolId=os.getenv('COGNITO_POOL_ID')
        )
        
        return jsonify({
            'data': response['UserPool']
        })
    except Exception as e:
        return jsonify({
            'message': e.response['Error']['Message']
        })
        
@app.route('/reset', methods=['GET'])
def reset():
    try:        
        response = client.list_users(
            UserPoolId=os.getenv('COGNITO_POOL_ID')
        )
                
        for user in response['Users']:
            client.admin_delete_user(
                UserPoolId=os.getenv('COGNITO_POOL_ID'),
                Username=user['Username']
            )
        
        return jsonify({
            'message': 'Ok'
        })
    except Exception as e:
        print(e)
        return jsonify({
            'message': e.response['Error']['Message']
        })
    
@api.route('/users', methods=['GET'])
def users():
    try:
        response = client.list_users(UserPoolId=os.getenv('COGNITO_POOL_ID'))
        
        return jsonify({
            'data': response['Users']
        })

    except Exception as e:
        print(e)
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 500)
    
app.register_blueprint(api)
app.run(host="0.0.0.0", port=port, debug=DEBUG)
