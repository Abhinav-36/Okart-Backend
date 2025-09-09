const jwt = require("jsonwebtoken");
const config = require("../config/config");
const { tokenTypes } = require("../config/tokens");

/**
 * Generate jwt token
 * - Payload must contain fields
 * --- "sub": `userId` parameter
 * --- "type": `type` parameter
 *
 * - Token expiration must be set to the value of `expires` parameter
 *
 * @param {ObjectId} userId - Mongo user id
 * @param {Number} expires - Token expiration time in seconds since unix epoch
 * @param {string} type - Access token type eg: Access, Refresh
 * @param {string} [secret] - Secret key to sign the token, defaults to config.jwt.secret
 * @returns {string}
 */
const generateToken = (userId, expires, type, secret = config.jwt.secret) => {

  let expiresIn;

  // If expires looks like a Unix timestamp in the past or future
  if (expires > 1000000000) { // crude check for seconds-since-epoch
    const now = Math.floor(Date.now() / 1000);
    expiresIn = expires - now; // duration in seconds from now
  } else {
    // treat as minutes
    expiresIn = expires * 60; // convert minutes to seconds
  }

  return jwt.sign(
    { sub: userId, type },
    secret,
    { expiresIn } // expiresIn in seconds
  );
  
};

/**
 * Generate auth token
 * - Generate jwt token
 * - Token type should be "ACCESS"
 * - Return token and expiry date in required format
 *
 * @param {User} user
 * @returns {Promise<Object>}
 *
 * Example response:
 * "access": {
 *          "token": "eyJhbGciOiJIUzI1NiIs...",
 *          "expires": "2021-01-30T13:51:19.036Z"
 * }
 */
const generateAuthTokens = async (user) => {
  let expires = new Date(Date.now() + config.jwt.accessExpirationMinutes * 60 * 1000);
  let tokenType = tokenTypes.ACCESS;

  let token = generateToken(user["_id"],config.jwt.accessExpirationMinutes,tokenType,config.jwt.secret);

  return {
    access: {
      token,
      expires
    }
  }
};

module.exports = {
  generateToken,
  generateAuthTokens,
};
