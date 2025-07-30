// server.js

// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser'); // For parsing request bodies
const bcrypt = require('bcrypt'); // For password hashing
const admin = require('firebase-admin'); // For Firebase Admin SDK
const { getFirestore, doc, getDoc, setDoc, updateDoc, collection, addDoc, query, where, getDocs } = require('firebase/firestore');
const crypto = require('crypto'); // Needed for crypto.randomUUID()

// Initialize the Express application
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON request bodies
app.use(bodyParser.json());

// --- Firebase Admin SDK Initialization ---
// IMPORTANT: This uses the Service Account Key.
// In a production environment, you would typically load this from environment variables
// or a secure configuration management system, NOT hardcode it.
const serviceAccount = {
    "type": "service_account",
    "project_id": "icegalaxy-dfefb",
    "private_key_id": "227c404eece505b0ab7f2c247072cd6227a2a6ac",
    "private_key":  "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0ACzKoGyGTzq9\nW+GQ96ERSP9l/he80hawUCo+Ouz49+IuikNYZ5htakLobTrWnA3yxAb134lboh6U\n/ZiyYcU6Ov3UEUrAwQQnflq8UpMb1Dv24MJD9xXB4A1KROSSdYx0cdHl0/PIltkE\nZiOjBIhFXjZ0gP8LnqN6eFFE2OD2OnAB+G4jHJw1fkln/PBgDXjwqoXgLT/L9x9y\nRKPUOMxMr8JIUf9EGoNKiDGPYXHbspXeu/Afkt92fW+H8ywUPRNCZyq97e2/nhll\nAYUfo+N0kt0wKngCpwBg4UwWPaVMQhkKQuscxNH87poTZz2/4Q7m8xM91lYa/AUX\n6qVV4eBFAgMBAAECggEAAgUMe52zZ+feSG39InTJqj/jEkjwK3LbGmJ+jtmZjIKN\naJgUPKOKiq1bIMWoMYY2JXSSPOO0uZ/+bx7P4B0QiNfVem2XYIFQVsk9moh9uzc9\n3ayY85GMBdn9HC//G+qINkt6Y6AY+s9zkgCy/qscc2W+duEyMuUlTGIzKi474D3N\nZtbReByTIeEXGYciiEiJbxfAkZEIYFjCvon0zOVUWqt3/OjzklIGkFhc3K7DpnDu\nUMIwmHFNE2+u+KJiB1HzLh+R1wD94mx7zeXe8ZwWa2bWKiIFd0yZZnW5vbuHxpJE\nHXtmVcSt4z6Nd92+Pl6XrZslkNjnC75zI1FWzh9c8wKBgQDeIIaN/CUQvacfsdEx\nFNtuLdSscSUhQCvx90wH04N4tN0RtvXFJzfbMR2sTp7ezgUlx8/T7NQxOJJEPu0P\n8CBs8E7cVhpkNqkEGbdI5KFYKDukyEyLjBLT6jgoRBseG6hLEJoNq2UkUYGkssAf\np6lGXVuVmQ8wIThItbWYyKqaiwKBgQDPcxryGugSnWsokW58NB0mAk2wCPjwDiRn\nx6m70J8rGD0UfL/GL2gZQwrsNnU+icp2o1HNUysLs1sE7V3ipCj2LazdQyheMB19\npTgwFnIhpVNGaTfGebxTCdnRs3OjdQEq9Fb342osHLz0EkM2s+MaRCq2GaGrUJax\n2MN7gzxabwKBgGSknBKtEiY5qAVmTgBNEPck8N2JDme4abDieaJ6JXGFkTy7hzPj\nBx3bbTRrEvSkqBRsKjA9eA8tMKiXUlYMWMTDRRf0M1UApyfidvciEDCfWhbZYkVA\nHC/ESdmEsjy8D06joQlchSElhPYYv5AYKUxmdF6d0RHfm17mZfdpxFLtAoGAZbkD\nlYQsGDSovxPRIYZMZL7saU19A/lrUJhPWpFJ+0+/Y7RoNT45xWliicGKbEgUx2f+\nTLhjezFPiHL8fo4Qp+ZtxXGQ8d6WF25Uxv+6p1TyKKyfdOtstSs3a+Sa56QQFogJ\nvTP+c/MDlIr/+mrrCY4zg2e+Jss1ma+462/GwHECgYBqDaoE7zMST7dj6Pa2imZj\nM+RCs5RePuLLYj6YABUEY3LVTIYJiR3c0oppAY1GeIt5NUZQECWl3KJ/4mjwijob\nWdGQJTKDdq4stPfRagzM8yVCDdf0YCaXa0Z6we79dMv5YhmaOikTqPULqCkx3b7T\nMKukjC4Ak9ZoAZ4mpElOCQ==\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-fbsvc@icegalaxy-dfefb.iam.gserviceaccount.com",
    "client_id": "105540458480353224730",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40icegalaxy-dfefb.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
};

// Initialize Firebase Admin SDK
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    // You might need to add a databaseURL if you're using Realtime Database
    // databaseURL: "https://YOUR_DATABASE_NAME.firebaseio.com"
});

// Get Firestore instance from the Admin SDK
const db = admin.firestore();

// We no longer need `currentAppId` or `currentUserId` in the same way,
// as the Admin SDK operates with elevated privileges and validates user tokens.
// For user-specific data, we'll rely on the UID from the verified ID token.

// --- Constants for Loyalty Program ---
const POINTS_PER_100_SPENT = 10;
const SPEND_THRESHOLD_FOR_POINTS = 100;
const POINT_VALUE_IN_RS = 1; // 1 point = 1 Rupee
const BCRYPT_SALT_ROUNDS = 10; // For password hashing

// --- Helper function to get user document reference ---
// Now uses the UID from the verified Firebase ID token
function getUserDocRef(uid) {
    // We'll use a fixed collection path for user data accessible by the Admin SDK
    return db.collection('users').doc(uid);
}

// --- Helper function to get orders collection reference ---
// Orders will be stored under a user's UID
function getOrdersCollectionRef(uid) {
    return db.collection('users').doc(uid).collection('orders');
}

// --- NEW: Middleware to Verify Firebase ID Token ---
// This middleware will protect endpoints that require an authenticated user.
const verifyIdToken = async (req, res, next) => {
    const idToken = req.headers.authorization?.split('Bearer ')[1];

    if (!idToken) {
        return res.status(401).json({ success: false, message: 'Authorization token not provided.' });
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken; // Attach decoded token (containing UID, phone_number, etc.) to the request
        next();
    } catch (error) {
        console.error('Error verifying Firebase ID token:', error);
        return res.status(403).json({ success: false, message: 'Invalid or expired token.', error: error.message });
    }
};

// --- NEW: Endpoint for User Registration/Login with Firebase ID Token and Password ---
// This endpoint now expects a Firebase ID Token from the frontend,
// which signifies that the user has already completed phone number verification on the client-side.
app.post('/register-or-login', async (req, res) => {
    const { idToken, password } = req.body; // Expecting Firebase ID Token and password from frontend

    if (!idToken) {
        return res.status(400).json({ success: false, message: 'Firebase ID Token is required.' });
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const uid = decodedToken.uid; // Firebase User ID
        const phoneNumber = decodedToken.phone_number; // Phone number from Firebase Auth

        if (!phoneNumber) {
            return res.status(400).json({ success: false, message: 'Phone number not found in Firebase ID Token.' });
        }

        const userDocRef = getUserDocRef(uid); // Use UID as the document ID
        const userDocSnap = await userDocRef.get(); // Use .get() for Admin SDK

        let isNewUser = false;
        let userData = {};

        if (!userDocSnap.exists) {
            // New user registration
            if (!password) {
                return res.status(400).json({ success: false, message: 'Password is required for new user registration.' });
            }
            const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
            userData = {
                uid: uid, // Store Firebase UID
                phoneNumber: phoneNumber, // Store phone number
                passwordHash: passwordHash,
                loyaltyPoints: 0,
                hasFirstTimeCoupon: true, // Assign 20% off coupon for first-time user
                createdAt: admin.firestore.FieldValue.serverTimestamp(), // Use server timestamp
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            };
            await userDocRef.set(userData); // Use .set() for Admin SDK
            isNewUser = true;
            console.log(`New user registered and data stored in Firestore: ${phoneNumber} (UID: ${uid}).`);
        } else {
            // Existing user login
            userData = userDocSnap.data();
            if (password) { // If password is provided, verify it
                if (!userData.passwordHash || !(await bcrypt.compare(password, userData.passwordHash))) {
                    return res.status(401).json({ success: false, message: 'Invalid password.' });
                }
            } else {
                // If no password provided, it means the user logged in via OTP on frontend.
                // We still update their last login time.
                console.log(`Existing user logged in via Firebase Auth (OTP/Client): ${phoneNumber} (UID: ${uid}).`);
            }
            await userDocRef.update({ updatedAt: admin.firestore.FieldValue.serverTimestamp() }); // Update last login time
        }

        let responseMessage = isNewUser ?
            'Registration successful! You received a 20% off coupon for your first purchase.' :
            'Login successful!';

        res.status(200).json({
            success: true,
            message: responseMessage,
            user: {
                uid: userData.uid,
                phoneNumber: userData.phoneNumber,
                loyaltyPoints: userData.loyaltyPoints,
                hasFirstTimeCoupon: userData.hasFirstTimeCoupon
            }
        });

    } catch (error) {
        console.error('Error during registration/login with Firebase ID Token:', error);
        res.status(500).json({ success: false, message: 'Failed to process registration/login.', error: error.message });
    }
});

// --- Apply verifyIdToken middleware to protected routes ---
// All routes below this line will require a valid Firebase ID token in the Authorization header.
app.use(verifyIdToken);

// --- Endpoint to Record a Purchase and Award Loyalty Points (Database Integrated) ---
// Now requires Firebase ID Token for authorization
app.post('/record-purchase', async (req, res) => {
    const { amountSpent } = req.body;
    const uid = req.user.uid; // Get UID from verified token
    const phoneNumber = req.user.phone_number; // Get phone number from verified token

    if (typeof amountSpent !== 'number' || amountSpent <= 0) {
        return res.status(400).json({ success: false, message: 'A valid positive amountSpent is required.' });
    }

    try {
        const userDocRef = getUserDocRef(uid);
        const userDocSnap = await userDocRef.get();

        if (!userDocSnap.exists) {
            // This should ideally not happen if user is authenticated, but good for robustness
            return res.status(404).json({ success: false, message: 'User data not found in Firestore. Please ensure registration is complete.' });
        }

        let user = userDocSnap.data();
        let pointsEarned = 0;

        // Calculate loyalty points
        if (amountSpent >= SPEND_THRESHOLD_FOR_POINTS) {
            pointsEarned = Math.floor(amountSpent / SPEND_THRESHOLD_FOR_POINTS) * POINTS_PER_100_SPENT;
            user.loyaltyPoints += pointsEarned;
        }

        // After a purchase, if the user had a first-time coupon, it's typically consumed.
        if (user.hasFirstTimeCoupon) {
            user.hasFirstTimeCoupon = false;
            console.log(`First-time coupon consumed for ${phoneNumber} (UID: ${uid}).`);
        }

        // Update user data in Firestore
        await userDocRef.update({
            loyaltyPoints: user.loyaltyPoints,
            hasFirstTimeCoupon: user.hasFirstTimeCoupon,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Record the order in the orders collection
        await getOrdersCollectionRef(uid).add({ // Add order to user's subcollection
            uid: uid,
            phoneNumber: phoneNumber,
            amountSpent: amountSpent,
            pointsEarned: pointsEarned,
            orderDate: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log(`Order recorded for ${phoneNumber} (UID: ${uid}).`);

        res.status(200).json({
            success: true,
            message: `Purchase recorded. Earned ${pointsEarned} points.`,
            user: {
                uid: user.uid,
                phoneNumber: user.phoneNumber,
                loyaltyPoints: user.loyaltyPoints,
                hasFirstTimeCoupon: user.hasFirstTimeCoupon
            }
        });
    } catch (error) {
        console.error('Error recording purchase:', error);
        res.status(500).json({ success: false, message: 'Failed to record purchase.', error: error.message });
    }
});

// --- Endpoint to Get User Loyalty Status (Database Integrated) ---
// Now requires Firebase ID Token for authorization
app.get('/user-status', async (req, res) => {
    const uid = req.user.uid; // Get UID from verified token
    const phoneNumber = req.user.phone_number; // Get phone number from verified token

    try {
        const userDocRef = getUserDocRef(uid);
        const userDocSnap = await userDocRef.get();

        if (!userDocSnap.exists) {
            return res.status(404).json({ success: false, message: 'User data not found in Firestore. Please ensure registration is complete.' });
        }

        const user = userDocSnap.data();

        res.status(200).json({
            success: true,
            user: {
                uid: user.uid,
                phoneNumber: user.phoneNumber,
                loyaltyPoints: user.loyaltyPoints,
                redeemableValue: user.loyaltyPoints * POINT_VALUE_IN_RS, // 1 point = 1 Rs
                hasFirstTimeCoupon: user.hasFirstTimeCoupon
            }
        });
    } catch (error) {
        console.error('Error fetching user status:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch user status.', error: error.message });
    }
});

// --- Endpoint to Redeem Loyalty Points (Database Integrated) ---
// Now requires Firebase ID Token for authorization
app.post('/redeem-points', async (req, res) => {
    const { pointsToRedeem } = req.body;
    const uid = req.user.uid; // Get UID from verified token
    const phoneNumber = req.user.phone_number; // Get phone number from verified token

    if (typeof pointsToRedeem !== 'number' || pointsToRedeem <= 0) {
        return res.status(400).json({ success: false, message: 'A valid positive number of pointsToRedeem is required.' });
    }

    try {
        const userDocRef = getUserDocRef(uid);
        const userDocSnap = await userDocRef.get();

        if (!userDocSnap.exists) {
            return res.status(404).json({ success: false, message: 'User data not found in Firestore. Please ensure registration is complete.' });
        }

        let user = userDocSnap.data();

        if (user.loyaltyPoints < pointsToRedeem) {
            return res.status(400).json({ success: false, message: `Insufficient points. You have ${user.loyaltyPoints} points.` });
        }

        user.loyaltyPoints -= pointsToRedeem;
        const discountValue = pointsToRedeem * POINT_VALUE_IN_RS;

        // Update user data in Firestore
        await userDocRef.update({
            loyaltyPoints: user.loyaltyPoints,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({
            success: true,
            message: `Successfully redeemed ${pointsToRedeem} points for a discount of Rs. ${discountValue}.`,
            discountApplied: discountValue,
            user: {
                uid: user.uid,
                phoneNumber: user.phoneNumber,
                loyaltyPoints: user.loyaltyPoints
            }
        });
    } catch (error) {
        console.error('Error redeeming points:', error);
        res.status(500).json({ success: false, message: 'Failed to redeem points.', error: error.message });
    }
});

// --- Wallet Endpoint (Database Integrated) ---
// Now requires Firebase ID Token for authorization
app.get('/wallet', async (req, res) => {
    const uid = req.user.uid; // Get UID from verified token
    const phoneNumber = req.user.phone_number; // Get phone number from verified token

    try {
        const userDocRef = getUserDocRef(uid);
        const userDocSnap = await userDocRef.get();

        if (!userDocSnap.exists) {
            return res.status(404).json({ success: false, message: 'User data not found in Firestore. Please ensure registration is complete.' });
        }

        const user = userDocSnap.data();

        res.status(200).json({
            success: true,
            wallet: {
                uid: user.uid,
                phoneNumber: user.phoneNumber,
                loyaltyPoints: user.loyaltyPoints,
                balanceInRs: user.loyaltyPoints * POINT_VALUE_IN_RS // Monetary value of loyalty points
            }
        });
    } catch (error) {
        console.error('Error fetching wallet details:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch wallet details.', error: error.message });
    }
});

// --- Endpoint to Get All Orders for a User (Database Integrated) ---
// Now requires Firebase ID Token for authorization
app.get('/orders', async (req, res) => {
    const uid = req.user.uid; // Get UID from verified token
    const phoneNumber = req.user.phone_number; // Get phone number from verified token

    try {
        // Query orders specific to this UID within the user's subcollection
        const ordersRef = getOrdersCollectionRef(uid);
        const querySnapshot = await ordersRef.orderBy('orderDate', 'desc').get(); // Order by date for better display

        const orders = [];
        querySnapshot.forEach((doc) => {
            orders.push({ id: doc.id, ...doc.data() });
        });

        res.status(200).json({
            success: true,
            message: `Found ${orders.length} orders for ${phoneNumber} (UID: ${uid}).`,
            orders: orders
        });
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch orders.', error: error.message });
    }
});


// --- Start the server ---
app.listen(PORT, () => {
    console.log(`Firebase Auth, Loyalty & Database Server running on http://localhost:${PORT}`);
    console.log('To run this, ensure you have the required Node.js libraries installed:');
    console.log('npm install express body-parser firebase-admin bcrypt');
    console.log('\n--- IMPORTANT ---');
    console.log('This backend now expects Firebase Phone Authentication to be handled on the CLIENT-SIDE.');
    console.log('The client (frontend) must send a valid Firebase ID Token to protected endpoints.');
    console.log('\n--- Endpoints ---');
    console.log('1. POST /register-or-login: { "idToken": "FIREBASE_ID_TOKEN_FROM_FRONTEND", "password": "your_secure_password" }');
    console.log('   - Registers new user (with 20% coupon and password) or logs in existing user (verifying password if provided).');
    console.log('   - Requires a Firebase ID Token obtained from client-side phone authentication.');
    console.log('2. POST /record-purchase: { "amountSpent": 1500 }');
    console.log('   - Requires Authorization: Bearer FIREBASE_ID_TOKEN_FROM_FRONTEND header.');
    console.log('   - Records a purchase, awards loyalty points, and potentially consumes first-time coupon. Stores data in Firestore.');
    console.log('3. GET /user-status');
    console.log('   - Requires Authorization: Bearer FIREBASE_ID_TOKEN_FROM_FRONTEND header.');
    console.log('   - Retrieves current loyalty points and coupon status for the authenticated user from Firestore.');
    console.log('4. POST /redeem-points: { "pointsToRedeem": 50 }');
    console.log('   - Requires Authorization: Bearer FIREBASE_ID_TOKEN_FROM_FRONTEND header.');
    console.log('   - Redeems specified loyalty points for a discount. Updates points in Firestore.');
    console.log('5. GET /wallet');
    console.log('   - Requires Authorization: Bearer FIREBASE_ID_TOKEN_FROM_FRONTEND header.');
    console.log('   - Returns loyalty points and their monetary value (balance) for the authenticated user from Firestore.');
    console.log('6. GET /orders');
    console.log('   - Requires Authorization: Bearer FIREBASE_ID_TOKEN_FROM_FRONTEND header.');
    console.log('   - Returns all recorded orders for the authenticated user from Firestore.');
});
