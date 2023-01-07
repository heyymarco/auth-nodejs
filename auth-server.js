import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import cors from 'cors'
import morgan from 'morgan';
import credentials from "./credentials.js";
import corsOptions from "./corsOptions.js";


dotenv.config();


const decodedKey = Symbol();


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
    const decoded = req[decodedKey];
    const {
        username,
        roles,
        meta,
        
        iat, exp,
    } = decoded;
    
    
    
    res.json({
        post: posts.filter((p) => p.username === username),
        by: decoded
    });
});

app.post('/login', (req, res) => {
    const { username } = req.body;
    
    
    
    const accessToken  = generateAccessToken(username, ['admin']);
    
    const refreshToken = generateRefreshToken(username);
    refreshTokens.push(refreshToken);
    
    res.json({
        accessToken,
        refreshToken,
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



function generateAccessToken(username, roles) {
    return jwt.sign({ username, roles }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
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

function generateRefreshToken(username) {
    return jwt.sign({ username }, process.env.REFRESH_TOKEN_SECRET);
}
function authenticateRefreshToken(req, res, next) {
    const token = req.body.token;
    if (!token) return res.sendStatus(401); // Unauthorized
    
    
    
    if (!refreshTokens.includes(token)) return res.sendStatus(403); // Forbidden
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (error, decoded) => {
        if (error) return res.sendStatus(403); // Forbidden
        
        
        
        const {
            username,
            roles,
            meta,
            
            iat, exp,
        } = decoded;
        const accessToken = generateAccessToken(username);
        
        
        
        res.json({
            accessToken,
        });
        next();
    });
}


app.listen(3001);