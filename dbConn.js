import dotenv from 'dotenv'
import mongoose from 'mongoose'

dotenv.config();

export const connectDb = async () => {
    try {
        await mongoose.connect(process.env.DB_URI, {
            useUnifiedTopology: true,
            useNewUrlParser: true,
        });
    } catch (err) {
        console.log(err);
    }
}