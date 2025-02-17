import datetime
import os
import re
from flask import Blueprint, Flask, json, make_response, request, jsonify
from dotenv import load_dotenv
from vendors.cognito import client, hash
from flask_cors import CORS  # new import


env = os.path.join(os.getcwd(), '.env')

if os.path.exists(env):
    load_dotenv(dotenv_path=env)
else:
    load_dotenv()

print(json.dumps(dict(os.environ), indent=2))
    
DEBUG = os.getenv('DEBUG') == 'true' or False
CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')

app = Flask(__name__)
CORS(app)  # enable CORS globally
port = os.getenv('PORT') or 8080

api = Blueprint('api', __name__, url_prefix='/api')

@api.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    print
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
        
        return jsonify({
            'session': response['Session']
        })
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({
            'message': 'Invalid username or password'
        }), 401)
        
@api.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    phone = data['phone']
    last_password_change = ""
    terms = {
        'payments': False,
    }
    
    attributes = [
        {
            'Name': 'email',
            'Value': username
        },
        {
            'Name': 'phone_number',
            'Value': phone
        },
        {
            'Name': 'custom:last_password_change',
            'Value': last_password_change
        },
        {
            'Name': 'custom:terms',
            'Value': json.dumps(terms)
        }
    ]
    
    try:
        client.sign_up(
            ClientId=os.getenv('COGNITO_CLIENT_ID'),
            Username=username,
            Password=password,
            SecretHash=hash(username, CLIENT_ID, CLIENT_SECRET),
            UserAttributes=attributes,
        )
        
        client.admin_confirm_sign_up(
            UserPoolId=os.getenv('COGNITO_POOL_ID'),
            Username=username,
        )
        
        client.admin_update_user_attributes(
            UserPoolId=os.getenv('COGNITO_POOL_ID'),
            Username=username,
            UserAttributes=[
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                },
                {
                    'Name': 'phone_number_verified',
                    'Value': 'true'
                }
            ]
        )
        
        return jsonify({
            'message': 'User created'
        })
    except client.exceptions.UsernameExistsException as e:
        print(e)
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 409)

@api.route('/auth/validate-otp', methods=['POST'])
def validate_otp():
    try:
        data = request.get_json()
        username = data['username']
        code = data['code']
        session = data['session']
        response = client.respond_to_auth_challenge(
            ClientId=os.getenv('COGNITO_CLIENT_ID'),
            ChallengeName='EMAIL_OTP',
            Session=session,
            ChallengeResponses={
                'USERNAME': username,
                'EMAIL_OTP_CODE': code,
                'SECRET_HASH': hash(username, CLIENT_ID, CLIENT_SECRET),
            }
        )
        
        return jsonify({
            'message': 'Ok',
            'data': {
                'accessToken': response['AuthenticationResult']['AccessToken'],
                'refreshToken': response['AuthenticationResult']['RefreshToken'],
                'idToken': response['AuthenticationResult']['IdToken'],
                'expiresIn': response['AuthenticationResult']['ExpiresIn'],
            }
        })
    
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({
            'message': 'Invalid code or session'
        }), 401)
    
    

@api.route('/auth/me', methods=['GET'])
def me():
    auth_header = request.headers.get('Authorization')
    token = re.match(r'Bearer (.*)', auth_header)[1] if auth_header else 'Bearer'
    
    try:
        response = client.get_user(
            AccessToken=token
        )
        
        return jsonify({
            'data': {
                'username': response['UserAttributes'][0]['Value'],
                'terms': json.loads(response['UserAttributes'][2]['Value']),
                'last_password_change': response['UserAttributes'][3]['Value']
            }
        })
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({
            'message': 'Invalid token'
        }), 401)
    
@api.route('/auth/send-password-recovery-link', methods=['POST'])
def send_password_recovery_link():
    data = request.get_json()
    username = data['username']
    
    try:
        response = client.forgot_password(
            ClientId=os.getenv('COGNITO_CLIENT_ID'),
            Username=username,
            SecretHash=hash(username, CLIENT_ID, CLIENT_SECRET),
        )
        
        user = client.admin_get_user(
            UserPoolId=os.getenv('COGNITO_POOL_ID'),
            Username=username,
        )
        
        print(user)
                
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
        response = client.confirm_forgot_password(
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
            'message': str(e)
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
        
        client.update_user_attributes(
            AccessToken=token,
            UserAttributes=[
                {
                    'Name': 'custom:last_password_change',
                    'Value': str(datetime.now())
                }
            ]
        )
        
        return jsonify({
            'message': 'Password changed'
        })
        
    except client.exceptions.NotAuthorizedException as e:
        return make_response(jsonify({
            'message': e.response['Error']['Message']
        }), 401)
        
@app.route('/auth/privacy-policy', methods=['POST'])
def privacy_policy():
    
    auth_header = request.headers.get('Authorization')
    token = re.match(r'Bearer (.*)', auth_header)[1] if auth_header else None
    
    if not token:
        return make_response(jsonify({
            'message': 'Invalid token'
        }), 401)
        
    try:
        client.update_user_attributes(
            AccessToken=token,
            UserAttributes=[
                {
                    'Name': 'custom:privacy_policy',
                    'Value': 'true'
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
            email = next(attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'email')
            if re.search(r'@maildrop\.cc$', email):
                client.admin_delete_user(
                    UserPoolId=os.getenv('COGNITO_POOL_ID'),
                    Username=user['Username']
                )
        
        return jsonify({
            'message': 'Ok'
        })
    except Exception as e:
        return jsonify({
            'message': e.response['Error']['Message']
        })
    
@api.route('/users', methods=['GET'])
def users():
    try:
        response = client.list_users(
            UserPoolId=os.getenv('COGNITO_POOL_ID')
        )
        
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
