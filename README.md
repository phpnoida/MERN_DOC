# System requirement :

node installed (node -v)
mongodb running 
pm2 install 
redis install and running 

------------------------------------------------------------------------------
# Export & Import 

module.exports =Email ;//for one file
module.exports ={httpLogin,httpLogout} //for multiple methods

const slug=require('slugify');//importing third party package
const controller =require('./../controllers/user');
const {httpLogin,httpLogout}=require('./../controllers/user');

------------------------------------------------------------------------------
# Folder setup
//create following folders

Dsobs/api
- controllers
- models
-  middlewares
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

------------------------------------------------------------------------------
# Models 
create a file in models folder user.js

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