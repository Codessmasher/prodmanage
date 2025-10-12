import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";


const userSchema = new mongoose.Schema({
    avatar: {
        type: {
            url: String,
            localPath: String
        },
        default: {
            url: "https://img.freepik.com/free-vector/blue-circle-with-white-user_78370-4707.jpg?t=st=1760272768~exp=1760276368~hmac=69bb58b7980b1a3b966886cb223a91d91c204a012c6d39068bca392277af0205&w=1480",
            localPath: ""
        }
    },
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    fullName: {
        type: String, 
        required: true,
        trim: true
    },  
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters"]
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    refreshToken: {
        type: String,
    },
    forgotPasswordToken: {
        type: String,
    },
    forgotPasswordExpiry: {
        type: Date,
    },
    emailVerificationToken: {
        type: String,
    },
    emailVerificationExpiry: {
        type: Date,
    }

},
    {
        timestamps: true
    }
);


userSchema.pre("save", async function (next) { 
    if (!this.isModified("password")) {
        return next();
    }   
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
}

userSchema.methods.generateAccessToken = function() { 
    return jwt.sign(    
        { _id: this._id, username: this.username, email: this.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRE }
    );
}

userSchema.methods.generateRefreshToken = function() { 
    return jwt.sign(    
        { _id: this._id, username: this.username, email: this.email },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRE }
    );
}

userSchema.methods.generateTempToken = function() {
    const unHashedToken = crypto.randomBytes(20).toString("hex");
    this.hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex");
    this.tokenExpiry = Date.now() + 2 * 60 * 60 * 1000; // 2 hours
    return {unHashedToken, hashedToken: this.hashedToken, tokenExpiry: this.tokenExpiry};
}

const User = mongoose.model("User", userSchema);

export default User;