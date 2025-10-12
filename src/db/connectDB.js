import mongoose from "mongoose";


export const connectDB = async () => {
    const url = process.env.MONGO_URL;
    try {
        await mongoose.connect(url);
        console.log("✅ MongoDB connected");
    } catch (error) {
        console.log("❌ Error connecting to MongoDB:", error);
        process.exit(1); // Exit the process with failure
    }
};
