const catchAsync = require('../utils/catchAsync');
const User = require('../model/userModel');
const generateOtp = require('../utils/generateOtp');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/email');
const AppError = require('../utils/appError');

const signToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

const createSendToken = (user, statusCode, res, message) => {
    const token = signToken(user._id);

    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    };
    res.cookie('jwt', token, cookieOptions);

    user.password = undefined;
    user.passwordConfirm = undefined;
    user.otp = undefined;

    res.status(statusCode).json({
        status: 'success',
        message,
        token,
        data: {
            user
        }
    });
};

exports.signup = catchAsync(async (req, res, next) => {
    const { email, password, passwordConfirm, username } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
        return next(new AppError('User already exists', 400));
    }

    const otp = generateOtp();

    const otpExpires = Date.now() + 24 * 60 * 60 * 1000;

    const newUser = await User.create({
        username,
        email,
        password,
        passwordConfirm,
        otp,
        otpExpires,
    });

    try {
        await sendEmail({
            email: newUser.email,
            subject: 'Your OTP for email verification',
            html: `<h1>Your OTP is ${otp}</h1>`
        });

        createSendToken(newUser, 201, res, 'User created successfully');

    } catch (error) {
        await User.findByIdAndDelete(newUser._id);
        return next(new AppError('There was an error sending email. Please try again later', 500));

    }

});

exports.verifyAccount = catchAsync(async (req, res, next) => {
    const { otp } = req.body;

    if (!otp) {
        return next(new AppError('Please provide OTP', 400));
    }

    const user = req.user;

    if(user.otp !== otp) {
        return next(new AppError('Invalid OTP', 400));
    }

    if(Date.now() > user.otpExpires) {
        return next(new AppError('OTP has expired', 400));
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;

    await user.save({validateBeforeSave: false});

    createSendToken(user, 200, res, 'Account verified successfully');

});

exports.resendOTP = catchAsync(async (req, res, next) => {
    const {email} = req.user;
    
    if(!email){
        return next(new AppError('Please provide email', 400));
    }

    const user = await User.findOne({email});

    if(!user){
        return next(new AppError('User not found', 404));
    }

    if(user.isVerified){
        return next(new AppError('User is already verified', 400));
    }

    const newOtp = generateOtp();

    const otpExpires = Date.now() + 24 * 60 * 60 * 1000;

    user.otp = newOtp;
    user.otpExpires = Date.now() + 24 * 60 * 60 * 1000;

    await user.save({validateBeforeSave: false});

    try {
        await sendEmail({
            email: user.email,
            subject: 'Your OTP for email verification',
            html: `<h1>Your OTP is ${newOtp}</h1>`
        });

        res.status(200).json({
            status: 'success',
            message: 'OTP sent successfully',
        });

    } catch (error) {
        user.otp=undefined;
        user.otpExpires=undefined;
        await User.findByIdAndDelete(user._id);
        return next(new AppError('There was an error sending email. Please try again later', 500));

    }

});

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return next(new AppError('Please provide email and password', 400));
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new AppError('Incorrect email or password', 401)); 
    }

    createSendToken(user, 200, res, 'Login successful');
});

exports.logout = catchAsync(async (req, res, next) => {
    res.cookie('token', 'loggedout', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
        secure:process.env.NODE_ENV === 'production'
    });
    res.status(200).json({
         status: 'success',
         message: 'Logged out successfully'
        });
});

exports.forgetPassword = catchAsync(async (req, res, next) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return next(new AppError('User not found', 404));
    }

    user.resetPasswordOTP = generateOtp();
    user.resetPasswordOTPExpires = Date.now() + 24 * 60 * 60 * 1000;

    await user.save({ validateBeforeSave: false });

    try {
        await sendEmail({
            email: user.email,
            subject: 'Your OTP for password reset',
            html: `<h1>Your OTP is ${user.resetPasswordOTP}</h1>`
        });

        res.status(200).json({
            status: 'success',
            message: 'OTP sent successfully',
        });

    } catch (error) {
        user.resetPasswordOTP=undefined;
        user.resetPasswordOTPExpires=undefined;
        await User.findByIdAndDelete(user._id);
        return next(new AppError('There was an error sending email. Please try again later', 500));

    }

});

exports.resetPassword = catchAsync(async (req, res, next) => {
        const { email, otp, password, passwordConfirm } = req.body;

        const user = await User.findOne({
            email,
            resetPasswordOTP: otp, 
            resetPasswordOTPExpires: { $gt: Date.now() } });
    
        if (!user) {
            return next(new AppError('Not User Found', 400));
        }
    
        user.password = password;
        user.passwordConfirm = passwordConfirm;
        user.resetPasswordOTP = undefined;
        user.resetPasswordOTPExpires = undefined;
    
        await user.save( { });
    
        createSendToken(user, 200, res, 'Password reset successful');
    });
