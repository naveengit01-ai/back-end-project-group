const express=require("express")
const mongoose=require("mongoose")
const app=express()
app.use(express.json())
mongoose.connect(
    "mongodb+srv://naveengit01_db_user:naveen9090@cluster0.ysqpjgz.mongodb.net/learn"
)
.then(()=>(console.log("db connect")))
.catch((error)=>console.log(error))

const userschema=mongoose.Schema({
    name:String,
    roll_no:Number
})
const data=mongoose.model("data",userschema)
app.post("/data",(req,res)=>{
    try{
    const user=new data(req.body)
    user.save()
    res.status(201).json("sucessfully inserted")
    }
    catch(err){
        res.status(500).json("something is error")
    }
})
app.get("/",async(req,res)=>{
    try{
        const stored=await data.find()
        res.json(stored)
    }
    catch(error){
        res.status(505).json("Error to fetch")
    }
})
app.listen(5000,()=>{
    console.log("Server is running")
})