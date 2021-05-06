import * as express from 'express'
import auth from './auth'

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.use('/auth', auth());
app.post('/health', (req, res) =>
    res.send('OK.'));

const port = process.env.PORT || 9001;
app.listen(port, () => {
    console.log(`Server started at port ${port}.`);
});
