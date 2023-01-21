import dotenv from 'dotenv';
import express from 'express';
import jwt from 'jsonwebtoken';
import cors from 'cors'
import cookieParser from 'cookie-parser'
import morgan from 'morgan';

import credentials from './credentials.js';
import corsOptions from './corsOptions.js';
import {randomBytes} from 'crypto'
import axios from 'axios'


dotenv.config();


const decodedKey = Symbol();
const refreshTokenKey = 'refreshToken';
const oauthPkceKey    = 'oauthPkce';


const posts = [
    { username: 'Nuzz', title: 'Post 1' },
    { username: 'Alice', title: 'Post 2' },
];

const refreshTokens = [];

const app = express();
app
.use(express.json())
.use(credentials) // before CORS!
.use(cors(corsOptions))
.use(cookieParser())
.use(morgan('combined'))
;

app.get('/posts', (req, res) => {
    res.json({
        hello: 'everyone'
    });
});
app.delete('/post', authenticateAccessToken, (req, res) => {
    const decoded = req[decodedKey];
    const {
        username,
        roles,
        meta,
        
        iat, exp,
    } = decoded;
    
    
    
    res.json({
        message: `deleted by: ${username}`
    });
});

app.post('/login', async (req, res) => {
    const { username, password, code, state } = req.body;
    if (code && (typeof(code) === 'string')) {
        try {
            const {
                provider,
                [oauthPkceKey] : oauthPkceCode1,
            } = JSON.parse(state) ?? {};
            if (!provider || !oauthPkceCode1) {
                // console.log('PKCE code missing');
                return res.sendStatus(401); // Unauthorized
            } // if
            
            const oauthPkceCode2 = req.cookies?.[oauthPkceKey];
            if (oauthPkceCode1 !== oauthPkceCode2) {
                // console.log('PKCE code mismatch');
                return res.sendStatus(401); // Unauthorized
            } // if
            
            
            
            // exchange the auth code for an access token
            try {
                const response = await axios.post('https://github.com/login/oauth/access_token', {
                    grant_type    : 'authorization_code',
                    client_id     : process.env.OAUTH_GITHUB_CLIENT_ID,
                    client_id     : process.env.OAUTH_GITHUB_CLIENT_SECRET,
                    redirect_uri  : 'http://localhost:3000/login',
                    code          : code,
                });
            }
            catch {
                return res.status(500);
            }
        }
        catch {
            // console.log('parse error');
            return res.sendStatus(401); // Unauthorized
        } // try
        
        
        
        return;
    } // if
    
    
    const [accessToken]  = generateAccessToken(username);
    
    const [refreshToken, refreshTokenExpires] = generateRefreshToken(username);
    refreshTokens.push(refreshToken);
    
    res.cookie(refreshTokenKey, refreshToken, {
        httpOnly : true,
        sameSite : 'none',
        secure   : true,
        maxAge   : refreshTokenExpires * 1000
    });
    res.json({
        access_token : accessToken,
    });
});

app.get('/login/github', (req, res) => {
    console.log('login with github...');
    
    const oauthPkceCode = randomBytes(20).toString('hex');
    
    res
    .cookie(oauthPkceKey, oauthPkceCode, {
        httpOnly : true,
        sameSite : 'none',
        secure   : true,
        maxAge   : 5 * 60 * 1000
    })
    .json({
        authUrl : 'https://github.com/login/oauth/authorize?' + (new URLSearchParams({
            response_type : 'code',
            client_id     : process.env.OAUTH_GITHUB_CLIENT_ID,
            redirect_uri  : 'http://localhost:3000/login',
            scope         : 'user public_repo',
            state         : JSON.stringify({
                provider       : 'github',
                [oauthPkceKey] : oauthPkceCode,
            }),
        })).toString(),
    })
});

app.post('/refresh', authenticateRefreshToken);

app.post('/logout', (req, res) => {
    const token = req.body.token;
    if (token) {
        const index = refreshTokens.findIndex((t) => t === token);
        if (index >= 0) {
            refreshTokens.splice(index, 1);
        } // if
    } // if
    
    
    
    res.clearCookie(refreshTokenKey, {
        httpOnly : true,
        sameSite : 'none',
        secure   : true,
    });
    res.sendStatus(204); // No Content Success, no need to navigate away from its current page
});



function getUserRoles(username) {
    return ['admin'];
}
function generateAccessToken(username, expiresInSeconds = 30) {
    return [
        jwt.sign(
            { username, roles: getUserRoles(username) },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: expiresInSeconds }
        ),
        expiresInSeconds,
    ];
}
function authenticateAccessToken(req, res, next) {
    const auth = req.headers['authorization'];
    const token = auth && auth.split(' ')[1];
    if (!token) return res.sendStatus(401); // Unauthorized
    
    
    
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
        if (error) return res.sendStatus(403); // Forbidden
        
        
        
        req[decodedKey] = decoded;
        next();
    });
}

function generateRefreshToken(username, expiresInSeconds = (24 * 60 * 60)) {
    return [
        jwt.sign(
            { username },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: expiresInSeconds }
        ),
        expiresInSeconds,
    ];
}
function authenticateRefreshToken(req, res, next) {
    const token = req.cookies?.[refreshTokenKey];
    console.log('token: ', token);
    if (!token) return res.sendStatus(401); // Unauthorized
    
    
    
    if (!refreshTokens.includes(token)) return res.sendStatus(403); // Forbidden
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (error, decoded) => {
        if (error) return res.sendStatus(403); // Forbidden
        
        
        
        const { username } = decoded;
        const [accessToken] = generateAccessToken(username);
        
        
        
        res.json({
            access_token : accessToken,
        });
        next();
    });
}


app.listen(3001);