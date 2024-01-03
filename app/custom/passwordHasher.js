const crypto = require('crypto');
const bcryptjs = require('bcryptjs');

const useCryptoFunc = (password) => {
    return crypto.createHash('sha256').update(password).digest('base64');
}

const useBcryptjsFunc = (password) => {
    return bcryptjs.hashSync(password, bcryptjs.genSaltSync(10));
}

const getHashedPassword = (password, isBcryptjs = true) => {
    let hashed = null;
    if (isBcryptjs)
        hashed = useBcryptjsFunc(password);
    else
        hashed = useCryptoFunc(password);
    return hashed;
}

const comparePasswords = (password, dbpassword) => {
    return bcryptjs.compareSync(password, dbpassword);
}

module.exports = { getHashedPassword, comparePasswords }