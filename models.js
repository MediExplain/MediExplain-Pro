const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { 
        type: String, 
        required: true, 
        unique: true,
        validate: {
            validator: function(v) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: props => `${props.value} is not a valid email address!`
        }
    },
    password: { 
        type: String, 
        required: true,
        minlength: 8
    },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    isVerified: { type: Boolean, default: false }
});

const ReportSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    type: { 
        type: String, 
        required: true,
        enum: ['blood_test', 'urine_test', 'imaging', 'pathology', 'other']
    },
    originalText: { type: String, required: true },
    analysis: { type: String, required: true },
    date: { type: Date, default: Date.now },
    tags: [String],
    isDeleted: { type: Boolean, default: false }
});

// Pre-save hooks
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

// Indexes
ReportSchema.index({ userId: 1, date: -1 });
ReportSchema.index({ tags: 1 });

const User = mongoose.model('User', UserSchema);
const Report = mongoose.model('Report', ReportSchema);

module.exports = { User, Report };
