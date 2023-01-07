import allowedOrigins from './allowedOrigins.js'



export default function credentials(req, res, next) {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Credentials', true);
    }
    next();
}