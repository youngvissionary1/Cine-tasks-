const { body, param, query, validationResult } = require('express-validator');

// Common validation rules
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array().map(err => ({
                field: err.param,
                message: err.msg
            }))
        });
    }
    next();
};

// User validation rules
const validateUserUpdate = [
    body('firstName')
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('First name must be 2-50 characters'),
    
    body('lastName')
        .optional()
        .trim()
        .isLength({ max: 50 })
        .withMessage('Last name must be less than 50 characters'),
    
    body('email')
        .optional()
        .trim()
        .isEmail()
        .withMessage('Valid email required')
        .normalizeEmail(),
    
    body('phone')
        .optional()
        .trim()
        .matches(/^\+?[\d\s-]{10,}$/)
        .withMessage('Valid phone number required'),
    
    validateRequest
];

// Movie validation rules
const validateMovie = [
    body('title')
        .trim()
        .isLength({ min: 3, max: 200 })
        .withMessage('Title must be 3-200 characters'),
    
    body('description')
        .optional()
        .trim()
        .isLength({ max: 2000 })
        .withMessage('Description must be less than 2000 characters'),
    
    body('year')
        .optional()
        .isInt({ min: 1900, max: new Date().getFullYear() + 5 })
        .withMessage('Valid year required'),
    
    body('genre')
        .optional()
        .trim()
        .isLength({ max: 100 })
        .withMessage('Genre must be less than 100 characters'),
    
    body('priceCoins')
        .optional()
        .isInt({ min: 0, max: 10000 })
        .withMessage('Price must be 0-10000 coins'),
    
    validateRequest
];

// Gig validation rules
const validateGig = [
    body('title')
        .trim()
        .isLength({ min: 10, max: 200 })
        .withMessage('Title must be 10-200 characters'),
    
    body('description')
        .trim()
        .isLength({ min: 50, max: 5000 })
        .withMessage('Description must be 50-5000 characters'),
    
    body('category')
        .isIn(['design', 'writing', 'development', 'video', 'marketing', 'business', 'other'])
        .withMessage('Valid category required'),
    
    body('budgetType')
        .isIn(['fixed', 'hourly', 'recurring'])
        .withMessage('Valid budget type required'),
    
    body('budgetMin')
        .isFloat({ min: 1000 })
        .withMessage('Minimum budget must be at least ₦1000'),
    
    body('budgetMax')
        .isFloat({ min: 1000 })
        .withMessage('Maximum budget must be at least ₦1000'),
    
    body('deadline')
        .isISO8601()
        .withMessage('Valid deadline date required')
        .custom(value => {
            if (new Date(value) < new Date()) {
                throw new Error('Deadline must be in the future');
            }
            return true;
        }),
    
    validateRequest
];

// Payment validation
const validatePayment = [
    body('amount')
        .isFloat({ min: 500 })
        .withMessage('Amount must be at least ₦500'),
    
    body('type')
        .isIn(['deposit', 'withdrawal', 'subscription'])
        .withMessage('Valid payment type required'),
    
    validateRequest
];

// Admin PIN validation
const validateAdminPin = [
    body('pin')
        .isLength({ min: 6, max: 6 })
        .withMessage('6-digit PIN required')
        .isNumeric()
        .withMessage('PIN must contain only numbers'),
    
    validateRequest
];

module.exports = {
    validateRequest,
    validateUserUpdate,
    validateMovie,
    validateGig,
    validatePayment,
    validateAdminPin
};