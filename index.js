import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors'
import helmet from 'helmet';
import morgan from 'morgan';


const db = [
    {title: 'Hello, world (again)!'}
]


const app =
    express()
    .use(helmet())
    .use(bodyParser.json())
    .use(cors())
    .use(morgan('combined'));

app.get('/', (reg, res) => {
    res.send(db);
});

app.delete('/my-data', (reg, res) => {
    res.send('deleted!');
});

app.listen(3001, () => {
    console.log('listening on port 3001');
})