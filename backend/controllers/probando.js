import User from "../models/User.js";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";

export const register = async(req, res) => {
    try {

        const salt= bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);

        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hash,
            photo: req.body.photo
        });
        await newUser.save();
        res.status(200).json({ success: true, message: "Successfully created"});
    } catch (err) {
        res.status(500).json({success: false, message: "Failed to create. Try again"});
    }
    
}

export const login = async(req, res) => {

    const email = req.body.email;

    try {
        const user = await User.findOne({email});
        const checkCorrectPassword = await bcrypt.compare(req.body.password, user.password);
        // if user doesn't exist
        if(!user){
            return res.status(404).json({success:false, message: "User not found"});
        }
        if(!checkCorrectPassword){
            return res.status(401).json({ success:false, message: "Incorrect email or password"});
        }
        const {password, role, ... rest} = user._doc

        // create jwt token
        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET_KEY,
            { expiresIn: '15d'}
        );

        res.cookie('accessToken', token, {
            httpOnly: true,
            expires:token.expiresIn
        }).status(200).json({success:true, message:'successfully login - cookies', data:{...rest}})

    } catch (err) {
        console.error(error); // Agrega esta línea
        res.status(500).json({ success: false, message: "Failed to login" });
    }
}

/*
TODO: VIENE EL TOKEN*/

import jwt from 'jsonwebtoken';
export const verifyToken = (req, res, next) =>{

    const token = req.cookies.accessToken

    if(!token){
        return res.status(401).json({ success: false, message: "You're not authorize - token"})
    }

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user)=> {
        if(err){
            return res.status(401).json({success :false ,message :"Invalid Token"})
        }
        req.user = user

    })
}