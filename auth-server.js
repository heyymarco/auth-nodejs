import dotenv from 'dotenv';
import express from 'express';
import jwt from 'jsonwebtoken';
import cors from 'cors'
import cookieParser from 'cookie-parser'
import morgan from 'morgan';

import credentials from './credentials.js';
import corsOptions from './corsOptions.js';


dotenv.config();


const decodedKey = Symbol();
const refreshTokenKey = 'refreshToken';


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

app.post('/login', (req, res) => {
    const { username } = req.body;
    
    
    
    const [accessToken]  = generateAccessToken(username);
    
    const [refreshToken, refreshTokenExpires] = generateRefreshToken(username);
    refreshTokens.push(refreshToken);
    
    res.cookie(refreshTokenKey, refreshToken, {
        httpOnly : true,
        sameSite : 'None',
        secure   : true,
        maxAge   : refreshTokenExpires * 1000
    });
    res.json({
        accessToken,
    });
});

app.get('/refresh', authenticateRefreshToken);

app.delete('/logout', (req, res) => {
    const token = req.body.token;
    if (token) {
        const index = refreshTokens.findIndex((t) => t === token);
        if (index >= 0) {
            refreshTokens.splice(index, 1);
        } // if
    } // if
    
    
    
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
            accessToken,
        });
        next();
    });
}


app.listen(3001);