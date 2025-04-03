const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({path: './.env'});
console.log(process.env.NODE_ENV);

const app   = require('./app');


const db = process.env.DB;
mongoose.connect(db).
    then(() => {
    console.log('DB connection successful');
    })
    .catch(err => {
        console.log(err);
    });


const port = process.env.PORT || 4000;  

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
