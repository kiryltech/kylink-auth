import * as express from "express";
import * as util from 'util'
import * as crypto from 'crypto'
import * as debug from 'debug'
import {URL} from 'url'
import {TedisPool} from "tedis";

const AUTH_CODE_TTL_MILLIS = 60000;
const LOG = debug('kylink:auth');
const redisUrl = new URL(process.env.REDIS_URL);

let redisOptions = {
    host: redisUrl.hostname,
    port: parseInt(redisUrl.port),
    timeout: 1000,
};
if (redisUrl.password) {
    redisOptions['password'] = redisUrl.password;
}
const tedisPool = new TedisPool(redisOptions);
const app = express();
const oauthConf = {
    clientId: process.env.OAUTH_CLIENT_ID,
    secret: process.env.OAUTH_SECRET,
    tokenSecret: process.env.OAUTH_TOKEN_SECRET,
    tokenTTL: parseInt(process.env.OAUTH_TOKEN_TTL),
};

app.use((req, res, next) => {
    const clientId = req.query.client_id ?
        req.query.client_id : req.body.client_id;
    if (oauthConf.clientId != clientId) {
        LOG(`Invalid clientId: ${clientId}`);
        res.status(401).send('Unauthorized.');
        return;
    }
    next();
});

app.get('/', async (req, res) => {
    if (req.query.p != oauthConf.secret) {
        LOG(`Incorrect auth secret code: ${req.query.p}`)
        res.status(401).send('Unauthorized.');
        return;
    }
    // @ts-ignore
    const redirectUrl = decodeURIComponent(req.query.redirect_uri);
    const code = crypto.randomBytes(128).toString('base64url');
    const tedis = await tedisPool.getTedis();
    try {
        await tedis.set(`kylink:code:${code}`, '');
        await tedis.pexpire(`kylink:code:${code}`, AUTH_CODE_TTL_MILLIS);
    } finally {
        tedisPool.putTedis(tedis);
    }
    res.redirect(util.format('%s?code=%s&state=%s',
        redirectUrl, code,
        req.query.state));
});

function jsonToBase64(json) {
    return Buffer.from(JSON.stringify(json), 'ascii').toString('base64url');
}

function base64ToJson(base64) {
    return JSON.parse(Buffer.from(base64, 'base64url').toString('ascii'));
}

function sign(unsignedToken: string) {
    return crypto.createHmac('sha256', oauthConf.tokenSecret)
        .update(unsignedToken)
        .digest().toString('base64url');
}

function generateAccessToken() {
    const header = {
        alg: 'HS256',
        typ: 'JWT',
    };
    const payload = {
        accessLevel: ['smarthome'],
        iat: Date.now() / 1000,
    };
    const unsignedToken = jsonToBase64(header) + '.' + jsonToBase64(payload);
    return unsignedToken + '.' + sign(unsignedToken);
}

app.use('/token', async (req, res) => {
    const grantType = req.query.grant_type ?
        req.query.grant_type : req.body.grant_type;
    LOG(`grant_type: ${grantType}`);
    const tedis = await tedisPool.getTedis();

    async function authCodeRequest() {
        if (!req.body.code ||
            !(await tedis.exists(`kylink:code:${req.body.code}`))) {
            LOG(`Invalid or expired code: ${req.body.code}`);
            res.status(401).send('Unauthorized.');
            return;
        }
        await tedis.del(`kylink:code:${req.body.code}`);
        const refreshToken = crypto.randomBytes(128).toString('base64url');
        await tedis.set(`kylink:refresh:${refreshToken}`, Date.now().toString());
        res.status(200).json({
            token_type: 'bearer',
            access_token: generateAccessToken(),
            refresh_token: refreshToken,
            expires_in: oauthConf.tokenTTL,
        });
    }

    async function refreshTokenRequest() {
        const refreshToken = req.query.refresh_token ?
            req.query.refresh_token : req.body.refresh_token;
        if (!(await tedis.exists(`kylink:refresh:${refreshToken}`))) {
            LOG(`Unknown refresh token: ${refreshToken}`);
            res.status(401).send('Unauthorized.');
            return;
        }
        res.status(200).json({
            token_type: 'bearer',
            access_token: generateAccessToken(),
            expires_in: oauthConf.tokenTTL,
        });
    }

    try {
        if (grantType == 'authorization_code') {
            await authCodeRequest();
        } else if (grantType === 'refresh_token') {
            await refreshTokenRequest();
        } else {
            LOG(`Grant type '${grantType}' is unsupported.`)
            res.status(400).send('Grant type is not supported.')
        }
    } finally {
        tedisPool.putTedis(tedis);
    }
});

app.get('/logout', (req, res) => {
    // @ts-ignore
    req.logout();
    req['session'] = null;
    res.redirect('/');
});

export default function auth() {
    return app;
}