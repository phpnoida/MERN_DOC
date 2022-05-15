# System requirement :

- node installed (node -v)
- mongodb running
- pm2 install
- redis install and running

---

# Export & Import

- module.exports =Email ;//for one file
- module.exports ={httpLogin,httpLogout} //for multiple methods

- const slug=require('slugify');//importing third party package
- const controller =require('./../controllers/user');
- const {httpLogin,httpLogout}=require('./../controllers/user');

---

# Folder setup

//create following folders

Dsobs/api

- controllers
- models
- middlewares
- routes
- data
- utils/common
- public
- views
- cron
- validations
- package.json
- .env
- .gitignore

//create package.json file for your project

- npm install -y -->first time create package.json
- npm install ----will install all packages from package.json file

//install npm packages

- npm i express@4
- npm i mongoose //we will install mongoose latest version i.e 6th
- npm i mongoose@5
- npm i dotenv

//uninstall packages which r not required

- npm uninstall jsownebtoken

//write script in package.json file to run project
package.json
"start":"NODE_ENV=production node server.js"
"start:dev":"NODE_ENV=development nodemon server.js"
"start:test":"NODE_ENV=test node server.js"

- npm start
- npm run start:dev
- npm run start:test

---

# Models

- create a file in models folder user.js

```
const mongoose=require('mongoose');
const userSchema = new mongoose.Schema({
    c1:{
        type:Number,
        default:0,
        select:false,
        trim:true,
        lowercase:true,
        unique:true,
        set:function(val){
            return Math.floor(val)
        },
        required:[true,'This is required'],
        min:[1,'min value must be 1'],
        max:[5,'max value not more than 5'],
        minlength:[3,''],
        maxlength:[5,''],
        enum:{
            values:['v1','v2','v3'],
            message:'please select only from v1,v2'
        }
    }
},{toJSON:{virtuals:true},toObject:{virtuals:true},timestamps:true})

//static method
userSchema.statics.autoPress = async function(roundId){
    console.log(this);//will point to current model
    const data = await this.findById();
    return data
}

//how to use static method in controller
//const data = await User.autoPress(roundId);

//instance method
userSchema.methods.strokePlay = async function(){
    const data = await this.find();
    return data;
}

//how to use instance method in controller
//await user.strokePlay();

//hooks or middleware in model
//there are 3:document , query , aggregate with pre and post

//doc middleware
userSchema.pre('save',async function(next){
    console.log(this);//points to current document being saved
    this.slug=slugify(this.name);
    if(!this.isModified('password')){
        return next();
    }
    this.password=await bcrypt.hash(this.password,12);
    next();//must not to forgot
})

//query middleware
userSchema.pre('find',function(next){
    console.log(this);//points to current query being executed
    await this.select('name email')
})

//creating virtual field
userSchema.virtual('fullName').get(function(){
    return `${this.firstName} ${this.lastName}`
})

//finally creating model out of schema
//constant name in capital because it model is class
const User=mongoose.model('User',userSchema);

//exporting this mdule
module.exports = User;
```

---

# Global Error Handler

- in middleware folder create a file globalErrorHandler.js
- express consider a method with 4 para and mainly starting with err as in - - 1st para as error handler method which express call when error occur
- concept is that calling next() with parameter will invoke this error file
- next({statusCode:400,message:'',status:false})

```
const AppError = require('./utils/AppError');


const handleCastErrorDB = err => {
  const message = `Invalid ${err.path}: ${err.value}.`;
  //converting mongoose error to operational error by invoking AppError
  //because in AppError we have a property isOperational :true
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = err => {
  const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];

  const message = `Duplicate field value: ${value}. Please use another value!`;
  return new AppError(message, 400);
};

const handleValidationErrorDB = err => {
  //we will convert object into array ,bcz map returns an array
  const errors = Object.values(err.errors).map(el => el.message);

  //we are join() bcz we are sending response in string ,if
  //u want to send array only then we can send errors as it is
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

const handleJWTError = () =>
  new AppError('Invalid token. Please log in again!', 401);

const handleJWTExpiredError = () =>
  new AppError('Your token has expired! Please log in again.', 401);

const sendDevError = (err,res)=>{
    res.status(err.statusCode).json({
        status:err.status,
        message:err.message,
        stack:err.stack
    })
}

const sendProdError =(err,res)=>{
    //trusted errors :let client know what wrong they r doing
    //ex:validation error , all errors which we are generating through
    //AppError() class
    if(err.isOperational){
        res.status(err.statusCode).json({
            status:err.status,
            message:err.message
        })
    }else{
        //unknow error like  third party error or unexpected error
        console.log('err production',err);
        //send generic message ,as we not want to leak errors
        res.status(500).json({
            status:'error',
            message:'Something Went Wrong'
        })
    }
}
const globalErrorHandler =(err,req,res,next)=>{
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error'
    if(process.env.NODE_ENV==='development'){
        sendDevError(err,res)
    }
    else if(process.env.NODE_ENV==='production'){
        let error = { ...err };
        if (error.name === 'CastError'){
            error = handleCastErrorDB(error);

        }
        if (error.code === 11000) error = handleDuplicateFieldsDB(error);
        if (error.name === 'ValidationError'){
            error = handleValidationErrorDB(error);
        }
        if (error.name === 'JsonWebTokenError') error = handleJWTError();
        if (error.name === 'TokenExpiredError'){
            error = handleJWTExpiredError();

        }
        sendProdError(error,res)
    }
}

module.exports=globalErrorHandler;
```

# AppError class

- go to common folder create a file AppError.js

```
class AppError extends  Error{
    constructor(message,statusCode){
        //parent class Error accept only 1 par i.e message
        super(message);
        this.statusCode=statusCode;
        this.status=`${this.statusCode}`.startsWith('4')?false:'error';
        this.isOperational=true;
        Error.captureStackTrace(this,this.constructor);
    }
}

module.exports=AppError;
```

---

# catchAsync Error of controller

- in controller using try and catch everywhere can dilute the readability
- go to common folder and create a file catchAsync.js

```
const catchAsync =(fn)=>{
    return async (req,res,next)=>{
        try{
          await fn(req,res,next)
        }catch(error){
            next(error)

        }
    }
}
module.exports=catchAsync;
```

---

# controllers

- go to controllers folder ,create a folder named user
- inside user folder create following files :
  - create.js
  - delete.js
  - update.js
  - get.js

create.js

```
const User = require('./../models/User');
const {StatusCodes}=require('http-status-code');
const AppError = require('./../common/AppError');
const catchAsync = require('./../common/catchAsync');

const httpCreate = catchAsync(async(req,res,next)=>{
    console.log('');
    //about req object
    //const {}=req.body;
    //const {}=req.params;
    //const {}=req.headers;
    //const {}=req.query;
    if(condition){
        return new AppError('',StatusCodes.)
    }

    res.status(StatusCodes.CREATED).json({
        status:true,
        data:data
    })
})

module.exports=httpCreate;
```

---

# routes

- go to routes folder and create a file with namee user.js

user.js

```
const express = require('express');
const httpCreate = require('./../controllers/create');
const httpGetAll = require('./../controllers/getAll');
//const controller = require('./../controllers/user');

const route=express.Router();
router.route('/user').post(httpCreate);
router.route('/users').get(httpGetAll);
router.route('/user/:userId').get().patch().delete();

module.exports=router;
```

---

# app.js

- this file will host all middlewares
- sequence of middlewares matters a lot

```
const express = require('express');
const cors = require('cors');
const helmet=require('helmet');
const mongoSanitize=require('express-mongo-sanitize');
const xss =require('xss-clean');
const userRoute=require('./routes/user');
const AppError =require('./common/AppError');
const globalErrorHandler=require('./common/globalErrorHandler');

const app =express();
app.use(cors());
app.options('*',cors());
app.use(express.json());
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use('/api',userRoute);
app.use('/api',tourRoute);

app.all("*",(req,res,next)=>{
    next(new AppError('invalid Url',404))
})

app.use(globalErrorHandler);

module.exports=app;
```

---

# database.js

```
const mongoose=require('mongoose');
const connectDB =()=>{
    if(process.env.NODE_ENV==='development'){
        mongoose.connect(process.env.DEV_DB_URL).then(()=>{
            console.log('Dev DB Connected')
        }).catch((err)=>{
            console.log('Dev DB Error',err)
        })
    }
    else if(process.env.NODE_ENV==='production'){
        mongoose.connect(process.env.PROD_DB_URL).then(()=>{
            console.log('Prod DB Connected')
        }).catch((err)=>{
            console.log('Prod DB Error',err)
        })

    }
}

module.exports=connectDB;
```

---

# server.js

```
const env=require('dotenv');
env.config();
//env.config({path:''})
const http=require('http');
const app =require('./app');
const connectDB=require('./database');
const server=http.createServer(app);
const PORT=process.env.PORT;

async function startServer(){
    await connectDB();
    server.listen(PORT,()=>{
        console.log('server is listening..')
    })
}
startServer(); //no need to use await
```

---
# validations in express
- validation in express can be done in 3 ways
- either in controller,either in model , either using 3rd party package
- let us see using 3rd party
- goto validations folder create a file named user.js

```
const {check,body,validationResult}=require('express-validator');

const validateLogin =()=>{
    return [
        check('email').isEmail().withMessage(''),
        check('phone').matches().withMessage(''),
        body('name').notEmpty().withMessage(''),
        body('city').isOptional({checkFalsy:true}).matches().withMessage(''),
        check('confirmPassword').custom((val,{req})=>{
            if(!val===req.body.password){
                throw new Error('not matched')
            }
            return true;
        })
    ]
}

const isValidated = (req,res,next)=>{
    const errors = validationResult(req);
    if(errors.isEmpty()){
        return next();
    }
    res.status(422).json({
        status:false,
        errors:errors.array()
    })
}

module.exports={validateLogin,isValidated}
```
- go to routes 
- const {validateLogin,isValidated}=require('./../validations/user');
- router.route('/login').post(validateLogin,isValidated,httpLogin);

---
# logging 
- can be done using two ways 
- first using morgan 
- second using winston so that we can save logs in db
- we have to clear db after every 15 days otherwise server will be out of space

- let us start with morgan , go to app.js file
```
const morgan =require('morgan');
//will log all incoming request to console
app.use(morgan('combined'));
//write error logs only in access.log file 
const accessLogStream =fs.createWriteStream(path.join(__dirname,'access.log'),{flags:'a'});
app.use(morgan('combined',{
  skip:function(req,res){
       return res.statusCode<400
  },
  stream:accessLogStream
  
}));
```

- let us now use winston
- create a file called logger.js in root folder
```

//creater logger.js file in root folder of the project
//we will use winston
//more details :https://www.section.io/engineering-education/logging-with-winston/

const {createLogger,transports,format}=require('winston');
const {timestamp,combine,json}=format;
require('winston-mongodb');

const logger = createLogger({
                transports:[
                  //can be multiple transports that's why array
                 new transports.MongoDB({
                            level:'error', // i want to log only errors
                            db:`mongodb://localhost:27017/final`,
                            options:{useUnifiedTopology: true},
                            collection:'server_logs',
                            format:combine(
                                timestamp(),
                                json()
                            ),
           
                        })
                  
                  ]
});
//if we are in dev env then we want to log to console also
if (process.env.NODE_ENV !== 'prod') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

module.exports=logger;
```
- now hook logger into globalErrorHandler file
```
//import logger file first //
logger.error(`${req.method} -${req.originalUrl} - ${err.message} -${err.statusCode} -${JSON.stringify(req.body)}`,{
            //metadata:err.stack
            metadata:'testing'
})
```




