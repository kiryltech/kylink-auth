import * as express from 'express'
import auth from './auth'

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.use('/auth', auth());

const port = process.env.PORT || 9001;
app.listen(port, () => {
    console.log(`Server started at port ${port}.`);
});
