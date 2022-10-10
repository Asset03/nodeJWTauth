const userModel = require('../models/user-model')
const bcrypt = require('bcrypt')
const uuid = require('uuid');
const mailService = require('./mail-service')
const tokenService = require('./token-service')
const UserDto = require('../dtos/user-dto')
const ApiError = require('../exceptions/api-error');


class userService{
    async registration(email,password){
        const candidate =  await userModel.findOne({email})
        if(candidate){
            throw ApiError.BadRequest(`User exist by this ${email}`)
        }
        const activationLink = uuid.v4();
        const hashPassword = await bcrypt.hash(password,3)
        const user = await userModel.create({email,password:hashPassword,activationLink})
        await mailService.sendActivationMail(email,`${process.env.API_URL}/api/activate/${activationLink}`)


        const userDto = new UserDto(user); // id,email,isActivated
        const tokens = tokenService.generateToken({...userDto})
        await  tokenService.saveToken(userDto.id,tokens.refreshToken)

        return {...tokens,user:userDto}
    }

    async activate(activationLink){
        const user = await userModel.findOne({activationLink})
        if(!user){
            throw ApiError.BadRequest("incorrect link for activation")
        }
        user.isActivated = true;
        await user.save()
    }


}

module.exports = new userService();
