from flask import Flask
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_restful import Resource, Api, reqparse
import boto3
import os
from datetime import datetime, timezone


class Token(Resource):
    def __init__(self, db, auth_table):
        self.db = db
        self.table = auth_table

    def create_token(self, api_key):
        response = self.db.get_item(
            TableName='sandbox_authentication',
            Key={
                "api_key": {
                    "S": api_key
                }
            }
        )

        if 'Item' in response.keys():
            access_token = create_access_token(identity=api_key)
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid api_key'}, 401

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('api_key', required=True)
        args = parser.parse_args()

        response = self.create_token(args['api_key'])
        return response


class Sandboxes(Resource):
    def __init__(self, db, account_table):
        self.db = db
        self.table = account_table

    @jwt_required
    def get(self):
        response = self.db.scan(
            TableName=self.table,
            FilterExpression='attribute_exists(account_id)'
        )

        return response['Items'], 200


class Sandbox(Resource):
    def __init__(self, db, account_table):
        self.db = db
        self.table = account_table

    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        # Request must include account_name, cloud_provider
        parser.add_argument('account_name', required=False)
        parser.add_argument('cloud_provider', required=True)
        parser.add_argument('uuid', required=False)
        parser.add_argument('guid', required=False)
        args = parser.parse_args()

        if not args['cloud_provider']:
            return {'message': 'cloud_provider must be provided'}

        if args['account_name'] and (not args['uuid'] or args['guid']):
            response = self.db.get_item(
                TableName=self.table,
                Key={
                    "account_name": {
                        "S": args['account_name']
                    },
                    "cloud_provider": {
                        "S": args['cloud_provider']
                    }
                }
            )

            if 'Item' in response:
                response = response['Item']
                return response, 200
            else:
                return {'message': 'account not found'}, 404

        elif not args['account_name'] and (args['uuid'] or args['guid']):
            if args['uuid'] and not args['guid']:
                response = self.db.scan(
                    TableName=self.table,
                    FilterExpression='#u = :uuid and cloud_provider = :cp',
                    ExpressionAttributeValues={
                        ":uuid": {
                            "S": args['uuid']
                        },
                        ":cp": {
                            "S": args['cloud_provider']
                        }
                    },
                    ExpressionAttributeNames={
                        "#u": "uuid"
                    },
                    ConsistentRead=True
                )
            elif args['guid'] and not args['uuid']:
                response = self.db.scan(
                    TableName=self.table,
                    FilterExpression='guid = :guid and cloud_provider = :cp',
                    ExpressionAttributeValues={
                        ":guid": {
                            "S": args['guid']
                        },
                        ":cp": {
                            "S": args['cloud_provider']
                        }
                    },
                    ConsistentRead=True
                )
            else:
                return {'message': 'guid and uuid are mutually exclusive'}

            if 'Items' in response:
                if len(response['Items']) == 1:
                    response = response['Items'][0]
                    return response, 200
                elif len(response['Items']) > 1:
                    return {'message': 'more than 1 account associated with uuid or guid'}, 404
                else:
                    return {'message': 'account not found'}, 404
        
        else:
            return {'message': 'Must provide a mutually exclusive account_name or uuid/guid'}, 404

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        # Request must include guid, owner_user
        # env_type, owner_email, note are optional and default to ""
        parser.add_argument('cloud_provider', required=True)
        parser.add_argument('guid', required=False, default="")
        parser.add_argument('uuid', required=False, default="")
        parser.add_argument('owner_name', required=False, default="")
        parser.add_argument('env_type', required=False, default="")
        parser.add_argument('owner_email', required=False, default="")
        parser.add_argument('note', required=False, default="")
        args = parser.parse_args()

        if not (args['guid'] or args['uuid']):
            return {'message': 'guid and/or uuid must be provided'}

        # Look for an account already assigned to the GUID
        if args['uuid'] and not args['guid']:
            existing_account = self.db.scan(
                TableName=self.table,
                FilterExpression='#u = :uuid and cloud_provider = :cp',
                ExpressionAttributeValues={
                    ":uuid": {
                        "S": args['uuid']
                    },
                    ":cp": {
                        "S": args['cloud_provider']
                    }
                },
                ExpressionAttributeNames={
                    "#u": "uuid"
                },
                ConsistentRead=True
            )
        elif args['guid'] and not args['uuid']:
            existing_account = self.db.scan(
                TableName=self.table,
                FilterExpression='guid = :guid and cloud_provider = :cp',
                ExpressionAttributeValues={
                    ":guid": {
                        "S": args['guid']
                    },
                    ":cp": {
                        "S": args['cloud_provider']
                    }
                },
                ConsistentRead=True
            )
        else:
            return {'message': 'guid and uuid are mutually exclusive'}

        if 'Items' in existing_account:
            if len(existing_account['Items']) == 1:
                response = existing_account['Items'][0]
                return response, 200
            elif len(existing_account['Items']) > 1:
                return {'message': 'more than 1 account associated with uuid or guid'}, 404
            # else:
            #     return {'message': 'account not found'}, 404

        # Get a list of available accounts
        accounts = self.db.scan(
            TableName=self.table,
            FilterExpression='available = :avail and attribute_exists(account_id) and cloud_provider = :cp',
            ExpressionAttributeValues={
                ":avail": {
                    "BOOL": True
                },
                ":cp": {
                    "S": args['cloud_provider']
                }
            },
            ConsistentRead=True
        )

        for account in accounts['Items']:
            try:
                response = self.db.update_item(
                    TableName=self.table,
                    Key={
                        "account_name": {
                            "S": account['account_name']['S']
                        },
                        "cloud_provider": {
                            "S": args['cloud_provider']
                        }
                    },
                    UpdateExpression='SET available = :new_avail, guid = :guid, #u = :uuid, env_type = :et, owner_name = :ou, owner_email = :oe, note = :note, provison_time = :pt',
                    ConditionExpression='available = :curr_avail',
                    ExpressionAttributeValues={
                        ":curr_avail": {
                            "BOOL": True
                        },
                        ":new_avail": {
                            "BOOL": False
                        },
                        ":guid": {
                            "S": args['guid']
                        },
                        ":uuid": {
                            "S": args['uuid']
                        },
                        ":et": {
                            "S": args['env_type']
                        },
                        ":ou": {
                            "S": args['owner_name']
                        },
                        ":oe": {
                            "S": args['owner_email']
                        },
                        ":note": {
                            "S": args['note']
                        },
                        ":pt": {
                            "S": datetime.now(timezone.utc).isoformat("T", "seconds")
                        }
                    },
                    ExpressionAttributeNames={
                        "#u": "uuid"
                    },
                    ReturnValues='ALL_NEW'
                )

                return response['Attributes'], 200

            except self.db.exceptions.ConditionalCheckFailedException:
                pass

        return {'message': 'no accounts available'}, 404

    @jwt_required
    def delete(self):
        parser = reqparse.RequestParser()
        # Request must include account_name
        # All other attributes will be ignored and set to empty strings
        parser.add_argument('account_name', required=True)
        parser.add_argument('cloud_provider', required=True)
        parser.add_argument('needs_cleanup', required=False,
                            default=True, type=bool)
        parser.add_argument('available', required=False,
                            default=False, type=bool)
        args = parser.parse_args()

        response = self.db.update_item(
            TableName=self.table,
            Key={
                "account_name": {
                    "S": args['account_name']
                },
                "cloud_provider": {
                    "S": args['cloud_provider']
                }
            },
            UpdateExpression='SET available = :avail, guid = :guid, #u = :uuid, env_type = :et, owner_name = :ou, owner_email = :oe, note = :note, needs_cleanup = :nc, deprovision_time = :dpt',
            ExpressionAttributeValues={
                ":avail": {
                    "BOOL": args['available']
                },
                ":guid": {
                    "S": ""
                },
                ":uuid": {
                    "S": ""
                },
                ":et": {
                    "S": ""
                },
                ":ou": {
                    "S": ""
                },
                ":oe": {
                    "S": ""
                },
                ":note": {
                    "S": ""
                },
                ":nc": {
                    "BOOL": args['needs_cleanup']
                },
                ":dpt": {
                    "S": datetime.now(timezone.utc).isoformat("T", "seconds")
                }
            },
            ExpressionAttributeNames={
                "#u": "uuid"
            },
            ReturnValues='ALL_NEW'
        )

        return response['Attributes'], 200

class Cleanup(Resource):
    def __init__(self, db, account_table):
        self.db = db
        self.table = account_table

    @jwt_required
    def get(self):
        response = self.db.scan(
            TableName=self.table,
            FilterExpression='needs_cleanup = :nc and available = :avail and attribute_exists(master_api_key)',
            ExpressionAttributeValues={
                ":nc": {
                    "BOOL": True
                },
                ":avail": {
                    "BOOL": False
                },
            }
        )
        
        return response['Items'], 200

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('account_name', required=True)
        parser.add_argument('cloud_provider', required=True)
        args = parser.parse_args()

        response = self.db.update_item(
            TableName=self.table,
            Key={
                "account_name": {
                    "S": args['account_name']
                },
                "cloud_provider": {
                    "S": args['cloud_provider']
                }
            },
            UpdateExpression='SET needs_cleanup = :nc, cleanup_time = :ct, needs_verify = :nv',
            ExpressionAttributeValues={
                ":nc": {
                    "BOOL": False
                },
                ":ct": {
                    "S": datetime.now(timezone.utc).isoformat("T", "seconds")
                },
                ":nv": {
                    "BOOL": True
                }
            },
            ReturnValues='ALL_NEW'
        )

        return response['Attributes'], 200

class Release(Resource):
    def __init__(self, db, account_table):
        self.db = db
        self.table = account_table

    @jwt_required
    # Get a list of accounts that have a cleanup_time but do not need cleanup
    def get(self):
        response = self.db.scan(
            TableName=self.table,
            FilterExpression='needs_verify = :nv and available = :avail and attribute_exists(master_api_key)',
            ExpressionAttributeValues={
                ":nv": {
                    "BOOL": True
                },
                ":avail": {
                    "BOOL": False
                }
            }
        )
        
        return response['Items'], 200

    @jwt_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('account_name', required=True)
        parser.add_argument('cloud_provider', required=True)
        args = parser.parse_args()

        response = self.db.update_item(
            TableName=self.table,
            Key={
                "account_name": {
                    "S": args['account_name']
                },
                "cloud_provider": {
                    "S": args['cloud_provider']
                }
            },
            UpdateExpression='SET available = :avail, needs_verify = :nv',
            ExpressionAttributeValues={
                ":avail": {
                    "BOOL": True
                },
                ":nv": {
                    "BOOL": False
                }
            },
            ReturnValues='ALL_NEW'
        )

        return response['Attributes'], 200

# Get all of the environment variables
account_table = os.environ.get('SANDBOX_ACCOUNT_DB')
auth_table = os.environ.get('SANDBOX_AUTHENTICATION_DB')
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_region = os.environ.get('AWS_REGION')
jwt_secret_key = os.environ.get('JWT_SECRET_KEY')

# Run using AWS dynamodb service if values set
# Otherwise, use local instance of dynamodb
if aws_access_key_id and aws_secret_access_key and aws_region:
    prod = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                 aws_secret_access_key=aws_secret_access_key, region_name=aws_region)
    db = prod.client('dynamodb')
    print("Using production dynamodb")
else:
    db = boto3.client('dynamodb', endpoint_url='http://localhost:8000')
    print("Using local development dynamodb")

# Init Flask, jwt, and api
application = Flask(__name__)
application.config['JWT_SECRET_KEY'] = jwt_secret_key
application.config['JWT_ACCESS_TOKEN_EXPIRES'] = 300
jwt = JWTManager(application)
api = Api(application)

# entrypoints for API
api.add_resource(Token, '/token', resource_class_args=(db, auth_table))
api.add_resource(Sandboxes, '/sandboxes',
                 resource_class_args=(db, account_table))
api.add_resource(Sandbox, '/sandbox',
                 resource_class_args=(db, account_table))
api.add_resource(Cleanup, '/sandbox/cleanup', resource_class_args=(db, account_table))
api.add_resource(Release, '/sandbox/release', resource_class_args=(db, account_table))


if __name__ == "__main__":
    application.run(debug=True)
