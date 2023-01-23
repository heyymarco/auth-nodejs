import mongoose from 'mongoose'
import { Schema } from 'mongoose'


const userSchema = new Schema({
    username : {
        type: String,
        required: true,
    },
    password : {
        type: String,
        required: true,
    },
    roles: [String]
});
export default mongoose.model('User', userSchema);