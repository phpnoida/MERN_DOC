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

---

# sending Emails

- create a file called Email.js in common folder

```
//sending email using AWS SES
const nodemailer = require('nodemailer');
const pug=require('pug');
const AWS = require('aws-sdk');

class Email{
    constructor(obj){
        this.obj=obj;
        this.from=`Chegg<${process.env.EMAIL_FROM}`
    }
    createTransporter(){
        if(process.env.NODE_ENV==='dev'){
          return nodemailer.createTransport({
                        host: "smtp.mailtrap.io",
                        port: 2525,
                        auth: {
                            user: "f0210fafe620a0",
                            pass: "3078eb3b3cd477"
                        }
                        })
        }
        //for production use aws ses
        AWS.config.update({
            accessKeyId: process.env.ACCESS_KEY,
            secretAccessKey: process.env.SECRET_KEY,
            region: process.env.REGION
        });
        return nodemailer.createTransport({
            SES: new AWS.SES({
                apiVersion: '2021-12-01'
            })
        })
    }

    async sendEmail(template,subject){
        const html=pug.renderFile(`${__dirname}/../views/${template}.pug`,{
            obj:this.obj
        });

        const mailOptions={
            from:this.from,
            to:this.obj.email,
            subject,
            html
        }
       await this.createTransporter().sendMail(mailOptions);

    }



    async sendConfirmation(){
        await this.sendEmail('confirmation','Product Order Confirmation')
    }

    async sendForgotPassword(){
        await this.sendEmail('forgot','Change Password')
    }
}

module.exports=Email;
```

- how to use Email Object in controller

```
const data={};//as per your need make object
await new Email(data).sendOTP();
```

- about pug template engine , you can convert HTML to Pug online
  otp.pug

```
//to pass dynamic value in any element
span=obj.name
h1=obj.email

//to pass dynamic values in an attribute
<img alt=`${obj.name}` src=`images/user/${obj.user.profilePic}`/>

//to pass dynamic value in other way
#{obj.name} (# is must) mostly it is used
```

-let app.js know that we are using pug as template engine

```
const path=require('path');
const pug=require('pug');

app.set('view engine','pug');
app.set('views',path.join(__dirname,'views'))
```

---

# Data Modelling

- Two types
- Embedded or Denormalized
- Normalized or referntial

- let us understand embedded first
- Note :embedded array should not grow indefinetely

models->user.js

```
const mongoose =require('mongoose');
const userSchema = new mongoose.Schema({
    c1:{
        type:Number
    },
    c2:{
        type:String
    },
    c3:{
        type:Boolean
    },
    c4:{
        type:Date
    },
    c5:{
        type:[Number]
        //type:[String]
    },
    c6:Object,
    c7:{
        id:{
            type:mongoose.Schema.Types.ObjectId,
            ref:'Product'
        },
        c71:{
            type:String
        }
    },
    //embedded
    c8:[
        {
            city:{
                type:String
            },
            state:{
                type:String
            },
            addressLine:{
                type:String
            },
            mobile:{
                type:Number
            }
        }
    ]
})
```

---

# All about mongoose queries

## create (post method)

```
//1st way
const data=await User.create(req.body);
const data = await User.create(insertObj);
console.log(data);
//2nd way
const user = await User.find();
user.name=req.body.name;
user.city=req.body.city;
const data = await user.save();
```

## fetch (get method)

```
const data = await User.find({});//give array of objects
const data=await User.findOne({}); //give 1 object
const data =await User.findById(id);//give 1 object
//comparison operator
await User.find({
    salary:20,
    salary:{$eq:20},
    salary:{$neq:20},
    salary:{$gte:20},
    salary:{$lte:40},
    purchaseDate:{$gte:169875432}
    city:{$in:['bhopal','gaya','pune']},
    $expr:{$gte:["$expense","$budget"]}
})
//logical operator
await User.find({
    //similary $or
    $and:[
        {salary:{$gte:20}},
        {salary:{$lte:70}}
    ]
})

//for array fields we have some more operator
//Type1:array field but not array of objects
await User.find({
    paritcipantsId:{
        $size:2,
        $elemMatch:{$eq:userId},
        $elemMatch:{$gte:20},
        $all:[
            {$elemMatch:{$eq:userId1}},
            {$elemMatch:{$eq:userId2}}
        ]
    }

})
//Type2:array of objects
await User.find({
    "address":{$elemMatch:{_id:addressId}},
    "address":{$elemMatch:{_id:addressId,state:'up'}}
},{"address.$":1})
```

## delete (delete)

```
const data = await User.findByIdAndDelete(id);
const data = await User.deleteOne({});
const data = await User.deleteMany({});
```

## delete parent and child records

```
const productId = req.params.id;
const product = await Product.findOne({_id:productId});
if(!product){
    return next(new AppError('invalid id',404))
}
await product.remove();

//now go to product schema
productSchema.pre('remove',async function(next){
    //this.model('modelName u want to go to')
    await this.model('Review').deleteMany({product:this._id})
})
```

## update (path)

- operators are
- $set,$inc,$mul,$push,$addToSet,$pop

```
const data =await User.findByIdAndUpdate(id,req.body,{new:true,runValidators:true});
const data = await User.findOneAndUpdate({},req.body);
const data = await User.updateOne();
const data = await User.updateMany();

//update particular field
const data = await User.findOneAndUpdate({

},{
    $set:{
        isStatus:true,
        mobile:70423232,
        email:''

    }
})

//increase counter
const data = await User.findOneAndUpdate({

},{
    $inc:{
        "comments":1
    }
})

//insert element in array
const data = await User.findByIdAndUpdate(id,{
    $push:{
        "likeBy":userId
    }
})

//remove element from array
const data = await User.findByIdAndUpdate(id,{
    $pull:{
        "likeBy":userId
    }
})

//insert or remove based on condition
const option =isLiked?"$pull":"$push";
const data =await User.findByIdAndUpdate(id,{
    [option]:{
        "likedBy":userId
    }
})

//insert in array of objects
const data =await User.findByIdAndUpdate(id,
    {
        $push:{
            "address":req.body.address
        }
    }
})

//remove from array of objects
const data = await User.findByIdAndUpdate(id,{
    $pull:{
        "address":req.body.address.addressId
    }
})

//update object in array of object
const data = await User.findOneAndUpdate({
    "address":{$elemMatch:{_id:addressId}}
},{
    $set:{
        "address.$":req.body.address
    }
})
```

--

# filter , sorting , searching ,pagination

- will write this code in getAllProducts handler in controller

```
const {brand,color,numericFilters,searchKeyword,sort,fieldList}=req.query;
const queryObj={$and:[]};

/*
implementing filters
frontend will send data like this
color red,blue,green
brand samsung,lg,voltas
*/
//filter1 i.e color
if(color){
    //converting string to array
    //[red,blue,green]
    const colorList=color.split(',');
    queryObj[$and].push({
        color:{$in:colorList}
    })
}
//filter2 i.e brand
if(brand){
    //converting string to array
    //[voltas,lg,samsung]
    const brandList=brand.split(',');
    queryObj[$and].push({
        brand:{$in:brandList}
    })
}

//implementing numeric filter
//ex price>30 or rating>4.5
//frontend will send numericFilters as key and in value they will send string separated by comma like price>40,ratings>4.5
if(numericFilters){
    console.log(numericFilters);//will be a string
    //like price>30,rating>4.5
    //mapping userfirendly to mongodb operator
    const operatorMap={
        '>':"$gt",
        '>=':"$gte",
        '=':'$eq',
        '<':"$lt"
    }
    const regEx=/\b(<|>|>=|<=|=|<)\b/g
    let filters=numericFilters.replace(regEx,(match)=>`-${operatorMap[match]-`);
    console.log(filters);
    //now our string from frontend will get converted into mongodb style
    //price-$gt-40,rating-$gt-4.5
    //pass all numberfilters of project in an array
    const options=['price','ratings'];
    filters=filters.split(',').forEach((item)=>{
        const [field,operator,value]=item.split('-');
        if(options.includes(field)){
            queryObject[field]={[operator]:Number(value)}
        }
    })
    console.log(queryObject);{price:{$gt:40},rating:{$gte:4.5}}
}


let custom_query = Product.find(queryObj);

//implementing searching using regularExpression
if(searchKeyword){
    custom_query.find({
        $or:[
            firstName:{new RegExp(`^{searchKeyword}`,'i')},
            city:{new RegExp(`.*{searchKeyword}.*`,'i')}
        ]
    })

}




//implementing sorting
//mainly frontend will send string like price or -price or discount or -disc
//frontend will send string like discount,-price (in case of multiple)
if(sort){
    const sortList=sort.split(',').join(' ');
    //sort('discount -price')-->we want like this
    custom_query=custom_query.sort(sortList);
}else{
    //setting default sorting
    custom_query=custom_query.sort('-createdAt');
}

//select or projection
//front end will send string like name,email,password
//at backend we need to do like select('name email passw')
if(fieldList){
    const fieldList=fieldList.split(',').join(' ');
    custom_query=custom_query.select(fieldList);

}

//pagination
const page=req.query.page*1||1;
const limit =req.query.limit*1||10;
const skip=(page-1)*limit;
custom_query=custom_query.skip(skip).limit(limit);

//finally executing
const data = await custom_query;

//sending response
res.status(200).json({
    status:true,
    data:data,
    totalRec:await Product.find() //must for pagination at fronend
})
```

---

# Referential Modelling

- Example to keep in mind about the structure
  title name price stock ---------------- reviews productId
  COLOGOTE 45 4 COOL 1
  bad 1
  good 1

```
//Step1 change in model
//product.js
//creating a virtual field for reviews in master table
productSchema.virtual('reviews',{
    localField:'_id',
    foreignField:'productId',
    ref:'Review',
    match: { ratings: 5 }
    count:true

})

//step2 chnage in review model
productId:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Product'
},
userID:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'User'
}
//make productId,userId collectively unique
reviewSchema.index({productId,userId},{unique:true})

//step3 change in routes
product.js
const reviewRoute=require();
router.use('/product/:productId/reviews',reviewRoute);

route.js
const router=express.Router({mergeParams:true});
router.route('/review').post();
router.route('/reviews').get();
router.route('/review/:reviewId').get().patch().delete()

//step4 populating in controller

//various types of populate syntax:

const data = await Product.find().populate({
    path:'reviews'//name given in virtual field
    select:'',
    options: { sort: { 'created_at': -1 } }
})

const data=await Review.find().populate({
    path:'productId',
    select:''
}).populate({
    path:'userId',
    select:''
})

//populating fron newly created record
const data = await User.create();
const finalData=data.populate({

}).execPopulate();

//nested populate from more than 2tables
const data = await Admin.find().populate({
    path:'roleId',
    select:'',
    populate:{
        path:'access.moduleId',
        select:''
    }
})
```

---

# Aggregate pipeline

```
const data = await User.aggregate([
    {$match:{}},
    {$unwind:"$players.playerId"},
    {$limit:9},
    {$skip:9},
    {$sort:{"players.score":1}},//no $ here
    {
        $group:{
            //_id:null
            _id:{
               playerId:"$players.playerId"


            },
            total:{$sum:"$players.score"}//$max,$min,$avg,$sum
            count:{$sum:1},
            details:{
                //push:"$$ROOT",
                push:{
                    firstName:"$firstName",
                    lastName:"$lastName"
                }
            }
        }
    }
])
```

---

# login with email/phone and otp

- create otp model as we will store otp in table not redis

```
code:{
    type:String,
    required:true
},
expiresIn:{
    type:Number,
    required:true
},
userId:{
    type:mongoose.Schema.Types.ObjectId
},
sub:{
    type:String,
    enum:{
        values:['user','admin'],
        message:''
    },
isVerified:{
    type:Boolean,
    default:false
},
attempted:{
    type:Number,
    default:0
}
}
```

- controller code , send otpId to frontend , send otp to user on email/phone

```
const httpLoginController=catchAsync(async(req,res,next)=>{
    const {email,phone,isAdmin}=req.body;
    let isEmail=false;
    let query;
    if(!isAdmin && (!phone or !email)){
        return next(new AppError('isAdmin and email or phone is must',400))
    }
    if(phone){
        query={
            phone:phone
        }

    }
    else if(email){
        query={
            email:email
        }
        isEmail=true;
    }
    let data;
    if(!isAdmin){
       data = await User.findOne(query);

    }else{
        data=await Admin.findOne(query);
    }

    console.log(data);
    if(!data){
        return next(new AppError('Not registered user',400))
    }
    //logic for OTP code
    const otpCode=Math.floor();
    //save otp in db or redis
    const otp=await OTP.create({
        code:otpCode,
        userId:data._id,
        sub:'user',//otp generated for user
        expiresIn:moment().unix()
    })
    console.log('otp',otp);
    //send otp to user on either email or phone
    if(isEmail){
        new Email({to:data.email,code:otpCode}).sendOTP();
    }else{
        //fire sms
    }
    //finally sending response to frontend
    res.status(200).json({
        status:true,
        otpId:otp._id
    })


})
```

- controller verify otp
- issue jwt access and refresh token

```
const verifyOTP=catchAsync(async(req,res,next)=>{
    const {otpId,code}=req.body;
    if(!otpId){
        return next(new AppError('otpId is must',400));
    }
    const data = await OTP.findById(otpId);
    console.log(data);
    if(!data){
        return next(new AppError('Invalid id',400));
    }
    const isExpired = await OTP.findOne({
        _id:otpId,
        expiresIn:{$gte:moment().now()}
    })
    if(!isExpired){
        return next(new AppError('otp expired',400))
    }
    const isCodeValid = await OTP.findOne({
        _id:otpId,
        code:code
    })
    if(!isCodeValid){
        await OTP.findByIdAndUpdate(otpId,{
            $inc:{
                attempted:1
            }
        })
        return next(new AppError('Wrong otp',400))
    }
    if(isCodeValid.isVerified){
        return next(new AppError('already verified',400))
    }
    await OTP.findByIdAndUpdate(otpId,{
        $set:{
            isVerified:true
        }
    })


    //let us decide it is user or admin from sub
    let userData;
    if(isCodeValid.sub==='user'){
        userData=await User.findById(isCodeValid.userId);
    }else{
        userData=await Admin.findById(isCodeValid.userId).populate({
            path:'roleId',
            populate:{
                path:'access.moduleId'
                select:''
            }
        });
    }

    //now time to send JWT token

    //first create accessToken with expiry of say 15mts or 30mts
    const accessToken=await getToken(userId,sub,access_secret,expiresIn);

    /*
    if we want to run our application in 1 phone only
    means log user out if logins into new phone
    like netflix
    otherwise you can ignore below check

    */
    const isAnyRefreshToken=await Token.findOne({
        userId:userId
    });
    //if yes then delete that previous refreshToken
    if(isAnyRefreshToken){
        await Token.findByIdAndDelete(isAnyRefreshToken.-id);

    }
    const refreshToken=await getToken(userId,sub,access_secret,expiresIn);

    //save refreshToken in db
    await Token.create({
        token:refreshToken,
        userId:userId,
        sub:sub,
        isValid:true,
        ip:String, //req.ip
        userAgent:String  //req.headers['user-agent']
    })

    res.status(200).json({
        status:true,
        data:userData,
        accessToken:accessToken,
        refreshToken:refreshToken
    })
})
```

---

# AccessToken and RefreshToken

- go to common folder and create a file token.js

token.js

```
const jwt=require('jsonwebtoken');

const getToken=(userId,sub,secretKey,expiresIn)=>{
    return new Promise((resolve,reject)=>{
        jwt.sign({
            _id:userId,
            sub:sub
        },secretKey,{expiresIn:expiresIn},(err,token)=>{
            if(err){
                reject('jwt token opernation not allowed')
            }else{
                resolve(token)
            }
        })
    })
}

module.exports=getToken;
```

---

# Logout

- we mainly delete the refreshToken

```
const httpLogout = catchAsync(async(req,res,next)=>{
    const {refreshToken}=req.body;
    if(!refreshToken){
        return next(new AppError('token is must',400))
    }
    //check valid refreshToken or not
    const isValid = await Token.findById(token);
    if(!isValid){
        return next(new AppError('invalid refresh tokenid',400))
    }
    //if valid then delete it from db
    await Token.findByIdAndDelete(token);
    res.status(200).json({
        status:true,
        message:'logout'
    })
})
```

---

# Getting AccessToken based on refreshToken

---

# requireSignIn

- go to middlewares folder and create a file called requireSignIn.js

```
const jwt = require('jsonwebtoken');

const requireSignIn = (req,res,next)=>{
    const {authorization}=req.headers;
    let token;
    if(authorization){
    token = authorization.split(' ')[1];

    }
    if(!token){
        return next(new AppError('access token is must',401))
    }
    jwt.verify(token,process.env.JWT_ACCESS_SECRET,(err,decoded)=>{
        if(err){
            return next(new AppError('Token Expired',401))
        }
        console.log(decoded);
        let currentUser;
        let sub;
        if(decoded.sub==='user'){
            currentUser= await User.findById(decoded._id);
            sub='user';

        }
        else if(decoded.sub==='admin'){
            currentUser= await Admin.findById(decoded._id);
            sub='admin';

        }
        req.currentUser=currentUser;
        req.sub=sub;
        next();
    })
}
```

---

# Roles and Access Level

- let us formulate 3 tables
- roles ,admins , modules
- admins table structure below
- \_id name email phone roleId
- modules table structure below
- \_id name icon seqId link
- roles table structure below
- \_id roleName accessLevel
  \_id moduleId c r u d

- go to middlewares folder and create a file rolesAllowedTo.js

```
const rolesAllowedTo = (...roles)=>{
    return (req,res,next)=>{
        if(!roles.includes(req.sub==='admin')){
          return next(new AppError('Not Allowed',403))
        }
        next();
    }


}
module.exports=rolesAllowedTo;
```

- how to use it
- go to routes

```
//if route is allowed for only admin access
router.route('/add/staff').post(requireSignIn,rolesAllowedTo('admin'),...);

//if route is allowed for access of both user and admin
router.route().get(requireSignIn,rolesAllowedTo('user','admin'),..)
```

---
