import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import cors from 'cors'
import morgan from 'morgan';
import credentials from "./credentials.js";
import corsOptions from "./corsOptions.js";


dotenv.config();


const userDataKey = Symbol();


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
.use(morgan('combined'))
;

app.get('/posts', (req, res) => {
    res.json({
        hello: 'everyone'
    });
});
app.get('/protected-posts', authenticateAccessToken, (req, res) => {
    const userDataEx = req[userDataKey];
    const {
        username,
        roles,
        meta,
        
        iat, exp,
    } = userDataEx;
    
    
    
    res.json({
        post: posts.filter((p) => p.username === username),
        by: userDataEx
    });
});

app.post('/login', (req, res) => {
    const { username } = req.body;
    const roles = ['admin'];
    const userData = {
        username,
        roles,
    };
    
    
    
    const accessToken = generateAccessToken(userData);
    
    const refreshToken = generateRefreshToken(userData);
    refreshTokens.push(refreshToken);
    
    res.json({
        accessToken,
        refreshToken,
        username,
        roles,
    });
});

app.post('/refresh', authenticateRefreshToken);

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



function generateAccessToken(userData) {
    return jwt.sign(userData, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
}
function authenticateAccessToken(req, res, next) {
    const auth = req.headers['authorization'];
    const token = auth && auth.split(' ')[1];
    if (!token) return res.sendStatus(401); // Unauthorized
    
    
    
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, userDataEx) => {
        if (error) return res.sendStatus(403); // Forbidden
        
        
        
        req[userDataKey] = userDataEx;
        next();
    });
}

function generateRefreshToken(userData) {
    return jwt.sign(userData, process.env.REFRESH_TOKEN_SECRET);
}
function authenticateRefreshToken(req, res, next) {
    const token = req.body.token;
    if (!token) return res.sendStatus(401); // Unauthorized
    
    
    
    if (!refreshTokens.includes(token)) return res.sendStatus(403); // Forbidden
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (error, userDataEx) => {
        if (error) return res.sendStatus(403); // Forbidden
        
        
        
        const {
            username,
            roles,
            meta,
            
            iat, exp,
        } = userDataEx;
        const userData = {
            username,
            roles,
            meta,
        };
        const accessToken = generateAccessToken(userData);
        
        
        
        res.json({
            accessToken,
        });
        next();
    });
}


app.listen(3001);