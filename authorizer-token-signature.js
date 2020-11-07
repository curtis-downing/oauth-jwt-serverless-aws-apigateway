'use strict';

const request = require('request');
const jws = require('jws');
const jwk2pem = require('pem-jwk').jwk2pem;
var AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});
var ddb = new AWS.DynamoDB.DocumentClient();

const handlers = module.exports = {};

module.exports.jwtverify = (event, context, callback) =>
{

    console.log("starting")
    console.log(event)

    if (!event.authorizationToken) {
        console.log("Header does not exist not exist")
       badToken(callback)
        return;

    }

    var token = event.authorizationToken; //This token is passed in header of request

    token = token.replace(/^Bearer /, '');
    token = token.replace(/^bearer /, ''); // Just incase someoen forgets to capatalize

    const decoded = jws.decode(token);

    if (!decoded) {
        console.log("Bad Token")
       badToken(callback)
        return;
    } else {

        const claims = safelyParseJSON(decoded.payload);

        if (!claims.iss ) {
            // console.log("no claims found")

        } else {
            console.log(`token info is ${claims.jti}`);
            var params = {
                TableName: 'token-' + process.env.ENV_NAME,
                Key: {
                    jti: claims.jti
                }
            }
            
            if (get_token_info(params)) {
                goodToken(options.event.methodArn, callback);
                return;
            }
            
            /*
            Also, the code will permit any Okta Token, in production this should not be used, but
            it works fine for test.

            */
            // token was not found in db
            console.log(`Token ${claims.jti} not found in DB, checking auth server`);
            if ((claims.iss.split("\/").length == 5)) {
                console.log("API Access Mgmt token")
                var keyUrl = claims.iss + "/v1/keys"

            } else {
                console.log("OIDC endpoint")
                var keyUrl = claims.iss + "/oauth2/v1/keys"
            }

            var options = {
                event: event,
                method: 'GET',
                url: keyUrl,
                headers:
                    {
                        'cache-control': 'no-cache'
                    }
            };

            request(options, function (error, response, body ) {


              //  console.log(options.event.authorizationToken)

                if (error) throw new Error(error);

                var keys = JSON.parse(body)
                var keygood = 0

                var i = 0 // keys.keys.length-1

                while (i < keys.keys.length) {
                    var key = keys.keys[i]
                    var pem = jwk2pem(key);
                    /*This is where the signature magic happens*/
                    if (jws.verify(token, key.alg, pem)) {
                        keygood = 1
                    }
                    i++
                }

                // Verify that the nonce matches the nonce generated on the client side (I am ignoring nonce for simplicity)
                // if (nonce !== claims.nonce) {
                //     res.status(401).send(`claims.nonce "${claims.nonce}" does not match cookie nonce ${nonce}`);
                //     return;
                // }
                //
                // Verify that the issuer is Okta, and specifically the endpoint that we
                // performed authorization against.
                // if (config.oidc.issuer !== claims.iss) {
                //     res.status(401).send(`id_token issuer ${claims.iss} does not match our issuer ${config.oidc.issuer}`);
                //     return;
                // }
                //
                // Verify that the id_token was minted specifically for our clientId
                // if (config.oidc.clientId !== claims.aud) {
                //     res.status(401).send(`id_token aud ${claims.aud} does not match our clientId ${config.oidc.clientId}`);
                //     return;
                // }
                //
                // Verify the token has not expired. It is also important to account for
                // clock skew in the event this server or the Okta authorization server has
                // drifted.

                const now = Math.floor(new Date().getTime() / 1000);
                const maxClockSkew = 300; // 5 minutes
                if (now - maxClockSkew > claims.exp) {
                        keygood = 0;
                    console.log("Token is more than 5 minutes old !, too slow")
                }
                //
                // // Verify that the token was not issued in the future (accounting for clock
                // // skew).
                if (claims.iat > (now + maxClockSkew)) {
                    console.log("Back to the Future, not supported")
                    keygood = 0;
                }

                if (keygood == 1) { // Token is good, generate aws policy
                    // save into db
                    var params = {
                        TableName: 'token-' + process.env.ENV_NAME,
                        Item: claims
                    }
                    set_token_info(params)
                    goodToken(options.event.methodArn, callback)

                } else {
                    badToken(callback)
                    return;

                }
            });
        }
    }
};

function badToken ( cb ){
    cb('No Token');
}

function goodToken(arn, cb) {
    cb(null, {
        context: {
            scope: "demo"
        },
        principalId: "Invoke",
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: "Allow",
                Resource: arn
            }]
        }
    });
}



function safelyParseJSON (json) {
    var parsed

    try {
        parsed = JSON.parse(json)
    } catch (e) {
        // Oh well, but whatever...
    }
    return parsed // Could be undefined!
}

function get_token_info(params) {
    ddb.get(params, function(err, data) {
      if (err) {
        console.log("Error", err);
        return false
      } else {
        console.log("Success", data.Item);
        return true
      }
    });
}

function set_token_info(params) {
    if (!params)
        throw new Error('params not set');    

    ddb.put(params, function(err, data) {
      if (err) {
        console.log("Error", err);
        return false
      } else {
        console.log("Success", data);
        return true
      }
    });
}
