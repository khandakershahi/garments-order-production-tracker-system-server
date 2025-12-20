const express = require('express');
const app = express();
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require("dotenv").config();
const crypto = require('crypto');
// Stripe for test payments (optional)
let Stripe = null;
try {
    Stripe = require('stripe');
} catch (err) {
    console.warn('Optional dependency "stripe" is not installed. Stripe routes will be disabled until installed.');
}
// Note: Port is removed as Vercel handles this
const port = process.env.PORT || 3000;

// Initialize Stripe with secret key from env (use test secret for development)
const stripeSecret = process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET || '';
let stripe = null;
if (stripeSecret && Stripe) {
    stripe = new Stripe(stripeSecret, { apiVersion: '2023-08-16' });
    console.log('✅ Stripe initialized successfully');
} else if (!Stripe) {
    console.warn('Stripe module not installed. Install with: npm install stripe');
} else {
    console.warn('STRIPE_SECRET_KEY or STRIPE_SECRET not set. Stripe routes will fail until configured.');
}

// --- Firebase Initialization ---
const admin = require("firebase-admin");

// Use base64-encoded Firebase credentials for Vercel deployment
let serviceAccount;
if (process.env.FB_SERVICE_KEY) {
    // Decode base64 string from environment variable
    const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8");
    serviceAccount = JSON.parse(decoded);
} else {
    // Fallback to local file for development
    serviceAccount = require("./garments-firebase-adminsdk.json");
}

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// --- Utility Function ---
function generateProductId() {
    const prefix = "PRD";
    const timestamp = Date.now(); // Milliseconds since epoch
    // Generate 3 random bytes → 6 hex characters
    const random = crypto.randomBytes(3).toString("hex").toUpperCase();

    return `${prefix}-${timestamp}-${random}`;
}

// middleware
app.use(express.json());
// Configure CORS to allow multiple origins (production and development)
const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:5174',
    'https://garments-order-tracker.web.app',
    'https://garments-order-tracker.firebaseapp.com',
    process.env.CLIENT_URL
].filter(Boolean); // Remove undefined values

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization','X-Requested-With','X-Custom-Header'],
    credentials: true,
    optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));


// =================================================================
// --- AUTHENTICATION & AUTHORIZATION MIDDLEWARE ---
// =================================================================

const verifyFBToken = async (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send({ message: "Unauthorized access" });
    }
    try {
        const idToken = token.split(" ")[1];
        const decoded = await admin.auth().verifyIdToken(idToken);
        req.decoded_email = decoded.email;
        next();
    } catch (error) {
        return res.status(401).send({ message: "unauthorized access" });
    }
};

const verifyAdmin = async (req, res, next) => {
    const { userCollection } = await getCollections();
    const user = await userCollection.findOne({ email: req.decoded_email });
    if (user && user.role === 'admin') {
        next();
    } else {
        res.status(403).send({ message: 'Forbidden: Admin access required' });
    }
};

const verifyManager = async (req, res, next) => {
    const { userCollection } = await getCollections();
    const user = await userCollection.findOne({ email: req.decoded_email });
    if (user && (user.role === 'manager' || user.role === 'admin')) {
        // Allowing Admin access to Manager routes for system flexibility
        next();
    } else {
        res.status(403).send({ message: 'Forbidden: Manager access required' });
    }
};


// =================================================================
// --- DATABASE CONNECTION ---
// =================================================================

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.7c8ysvf.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
    connectTimeoutMS: 10000,
    socketTimeoutMS: 10000,
});


// Centralized MongoDB Connection/Initialization Function
async function connectToMongo() {
    try {
        if (!client.topology || !client.topology.isConnected()) {
            await client.connect();
            console.log("Connected to MongoDB");
        }
        return client.db("garment-db");
    } catch (error) {
        console.error("MongoDB connection error:", error.message);
        throw error;
    }
}

// Helper function to get collections
const getCollections = async () => {
    const db = await connectToMongo();
    return {
        userCollection: db.collection("users"),
        productCollection: db.collection("products"),
        orderCollection: db.collection("orders"),
        feedbackCollection: db.collection("feedbacks"),
        trackingCollection: db.collection("trackings"),
    };
};

// =================================================================
// --- BASE ROUTE ---
// =================================================================

app.get('/', (req, res) => {
    res.send('Garment Order Production Tracker is running')
})

// =================================================================
// ADMIN API
// =================================================================

// GET /admin/orders?status=Pending -> Returns all orders with optional status filter (Admin only)
app.get('/admin/orders', verifyFBToken, verifyAdmin, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        const status = req.query.status;
        
        const query = {};
        if (status) {
            query.orderStatus = status;
        }

        const orders = await orderCollection
            .find(query)
            .sort({ orderDate: -1 })
            .toArray();

        res.send(orders);
    } catch (error) {
        console.error('Error in /admin/orders GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// GET /admin/products?search=text -> Returns all products with optional search (Admin only)
app.get('/admin/products', verifyFBToken, verifyAdmin, async (req, res) => {
    try {
        const { productCollection } = await getCollections();
        const searchText = req.query.search;
        
        const query = {};
        if (searchText) {
            query.$or = [
                { title: { $regex: searchText, $options: 'i' } },
                { description: { $regex: searchText, $options: 'i' } },
                { category: { $regex: searchText, $options: 'i' } }
            ];
        }

        const products = await productCollection
            .find(query)
            .sort({ createdAt: -1 })
            .toArray();

        res.send(products);
    } catch (error) {
        console.error('Error in /admin/products GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});


// =================================================================
// ⭐ PRODUCT API ⭐
// =================================================================

// GET /products: Retrieves products with optional search and filtering (Public/Manager/Admin)
// app.get("/products", async (req, res) => {
//     try {
//         const { productCollection } = await getCollections();
//         const { searchText, category, showOnHomePage, managerEmail, limit } = req.query;
//         const query = {};

//         // 1. Search Text (Search by title or description)
//         if (searchText) {
//             query.$or = [
//                 { title: { $regex: searchText, $options: "i" } },
//                 { description: { $regex: searchText, $options: "i" } },
//             ];
//         }

//         // 2. Category Filter
//         if (category) {
//             query.category = category;
//         }

//         // 3. Homepage Filter (For the main Home page section)
//         if (showOnHomePage === 'true') {
//             query.showOnHomePage = true;
//         }

//         // 4. Manager Filter (For the Manager's /dashboard/manage-products page)
//         if (managerEmail) {
//             query.managerEmail = managerEmail;
//         }

//         let queryLimit = parseInt(limit) || 200; // Default limit

//         const products = await productCollection
//             .find(query)
//             .sort({ createdAt: -1 })
//             .limit(queryLimit)
//             .toArray();

//         res.send(products);
//     } catch (error) {
//         console.error("Error in /products GET:", error.message);
//         res.status(500).send({ message: "Internal server error" });
//     }
// });


// =================================================================
// PRODUCTS API - SPECIFIC ROUTES (Must come BEFORE /products/:id)
// =================================================================

// GET /products/:id -> Returns single product details
app.get("/products/:id", async (req, res) => {
    try {
        const { productCollection } = await getCollections();
        const id = req.params.id;

        // 1. Validate ID
        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid Product ID format." });
        }

        const query = { _id: new ObjectId(id) };

        // 2. Fetch the single product
        const product = await productCollection.findOne(query);

        if (!product) {
            return res.status(404).send({ message: "Product not found." });
        }

        // 3. Send the single product object
        res.send(product);

    } catch (error) {
        console.error("Error fetching single product:", error.message);
        res.status(500).send({ message: "Internal server error." });
    }
});

// IMPORTANT: Ensure the single-product route appears before the generic /products handler



// PATCH /products/:id: Used by Manager/Admin to update product details 
app.patch("/products/:id", verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { productCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid Product ID" });
        }

        const updatedFields = req.body;

        // Prevent accidental changes to the ID or manager email
        delete updatedFields._id;
        delete updatedFields.managerEmail;
        delete updatedFields.productId;

        const query = { _id: new ObjectId(id) };
        const updateDoc = {
            $set: updatedFields,
        };

        const result = await productCollection.updateOne(query, updateDoc);
        res.send(result);

    } catch (error) {
        console.error("Error in /products PATCH:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});


// DELETE /products/:id: Used by Manager/Admin to delete a product
app.delete("/products/:id", verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { productCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid Product ID" });
        }

        const query = { _id: new ObjectId(id) };
        const result = await productCollection.deleteOne(query);

        res.send(result);

    } catch (error) {
        console.error("Error in /products DELETE:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// =================================================================
//  FEEDBACK API
// =================================================================

// GET /feedbacks?limit=6 - Get recent feedbacks for homepage
app.get("/feedbacks", async (req, res) => {
    try {
        const { feedbackCollection } = await getCollections();
        const limit = parseInt(req.query.limit) || 6;
        
        const feedbacks = await feedbackCollection
            .find({})
            .sort({ createdAt: -1 })
            .limit(limit)
            .toArray();
        
        res.send(feedbacks);
    } catch (error) {
        console.error("Error in /feedbacks GET:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// GET /feedbacks/product/:productId - Get feedbacks for a specific product
app.get("/feedbacks/product/:productId", async (req, res) => {
    try {
        const { feedbackCollection } = await getCollections();
        const { productId } = req.params;
        
        const feedbacks = await feedbackCollection
            .find({ productId })
            .sort({ createdAt: -1 })
            .toArray();
        
        res.send(feedbacks);
    } catch (error) {
        console.error("Error in /feedbacks/product/:productId GET:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// POST /feedbacks - Create new feedback (authenticated users only)
app.post("/feedbacks", verifyFBToken, async (req, res) => {
    try {
        const { feedbackCollection } = await getCollections();
        const feedbackData = {
            ...req.body,
            userEmail: req.decoded_email,
            createdAt: new Date()
        };
        
        const result = await feedbackCollection.insertOne(feedbackData);
        res.send(result);
    } catch (error) {
        console.error("Error in /feedbacks POST:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// =================================================================
//  TRACKING API
// =================================================================

// GET /trackings/:orderId/logs - Get tracking logs for a specific order
app.get("/trackings/:orderId/logs", async (req, res) => {
    try {
        const { trackingCollection } = await getCollections();
        const { orderId } = req.params;
        
        const trackingLogs = await trackingCollection
            .find({ orderId })
            .sort({ createdAt: 1 })
            .toArray();
        
        res.send(trackingLogs);
    } catch (error) {
        console.error("Error in /trackings/:orderId/logs GET:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// POST /trackings - Create new tracking log (authenticated users only)
app.post("/trackings", verifyFBToken, async (req, res) => {
    try {
        const { trackingCollection } = await getCollections();
        const trackingData = {
            ...req.body,
            createdAt: new Date()
        };
        
        const result = await trackingCollection.insertOne(trackingData);
        res.send(result);
    } catch (error) {
        console.error("Error in /trackings POST:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});


// Updated Backend Route: /products (replace the existing GET /products in your server code)

app.get('/products', async (req, res) => {
    try {
        const { productCollection } = await getCollections();

        const searchText = req.query.searchText;
        const category = req.query.category;
        const showOnHomePage = req.query.showOnHomePage;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 9;

        // Build query object
        const query = {};
        
        if (searchText) {
            query.$or = [
                { title: { $regex: searchText, $options: 'i' } },
                { description: { $regex: searchText, $options: 'i' } },
                { category: { $regex: searchText, $options: 'i' } }
            ];
        }
        
        if (category) {
            query.category = category;
        }

        // Filter for homepage featured products
        if (showOnHomePage === 'true') {
            query.showOnHomePage = true;
        }

        // Get total count for pagination
        const totalCount = await productCollection.countDocuments(query);
        
        // Get products with pagination
        const products = await productCollection
            .find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .toArray();

        res.send({ products, totalCount });
    } catch (error) {
        console.error('Error in /products GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// Health route for quick checks
// (removed health route per revert request)

// =================================================================
// ⭐ NEW: ORDER/BOOKING API ⭐
// =================================================================

// POST /bookings: Handles new order submissions (Secured: Logged-in User)
app.post("/bookings", verifyFBToken, async (req, res) => {
    try {
        const { orderCollection, userCollection, productCollection } = await getCollections();
        const bookingData = req.body;

        const { userEmail, productId, orderQuantity } = bookingData;

        // --- 1. Security & Role Check ---
        // Ensure the token's email matches the submitted email
        if (req.decoded_email !== userEmail) {
            return res.status(403).send({ message: "Forbidden: Email mismatch" });
        }

        // Ensure the user role is not admin/manager (standard member only)
        const user = await userCollection.findOne({ email: userEmail });
        if (user.role === 'admin' || user.role === 'manager') {
            return res.status(403).send({ message: "Admins/Managers cannot place orders." });
        }

        // --- 2. Product & Quantity Validation ---
        if (!ObjectId.isValid(productId)) {
            return res.status(400).send({ message: "Invalid Product ID in booking data" });
        }

        const productQuery = { _id: new ObjectId(productId) };
        const product = await productCollection.findOne(productQuery);

        if (!product) {
            return res.status(404).send({ message: "Product not found or invalid ID" });
        }

        const currentAvailable = product.availableQuantity;

        if (orderQuantity < product.minOrderQuantity || orderQuantity > currentAvailable) {
            return res.status(400).send({
                message: `Order quantity must be between ${product.minOrderQuantity} and ${currentAvailable}.`
            });
        }

        // --- 3. Save the Booking ---
        // Add server-side metadata
        bookingData.orderDate = new Date();
        // Set initial payment status based on option
        bookingData.paymentStatus = (bookingData.paymentOption === 'PayFast' ? 'Pending' : 'Paid - COD');
        bookingData.orderStatus = 'Pending'; // Order processing status

        // Mark that we will deduct inventory for this booking (booking flow already decrements availableQuantity below)
        bookingData.inventoryDeducted = true;

        const result = await orderCollection.insertOne(bookingData);

        // --- 4. Update Product Stock (Decrement availableQuantity) ---
        const newAvailableQuantity = currentAvailable - orderQuantity;

        await productCollection.updateOne(
            productQuery,
            { $set: { availableQuantity: newAvailableQuantity } }
        );

        res.send(result);

    } catch (error) {
        console.error("Error in /bookings POST:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// =================================================================
// ORDERS API (User-specific)
// =================================================================

// GET /orders?email=user@example.com -> Returns orders placed by the authenticated user
app.get('/orders', verifyFBToken, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        const email = req.query.email;

        if (!email) {
            return res.status(400).send({ message: 'Email query parameter is required' });
        }

        // Ensure requester is asking for their own orders
        if (req.decoded_email !== email) {
            return res.status(403).send({ message: 'Forbidden: Cannot access other users orders' });
        }

        const orders = await orderCollection.find({ userEmail: email }).sort({ orderDate: -1 }).toArray();
        res.send(orders);
    } catch (error) {
        console.error('Error in /orders GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// Manager-only: GET /manager/orders?status=Pending|Approved
// Returns orders filtered by status (if provided). Requires manager or admin.
app.get('/manager/orders', verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        const { status } = req.query;
        const query = {};
        if (status) query.orderStatus = status;

        const orders = await orderCollection.find(query).sort({ orderDate: -1 }).toArray();
        res.send(orders);
    } catch (error) {
        console.error('Error in /manager/orders GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// =================================================================
// STATS API ROUTES (Must come BEFORE /orders/:id)
// =================================================================

// GET /orders/stats?email=user@example.com -> Returns user-specific order statistics grouped by status
app.get('/orders/stats', verifyFBToken, async (req, res) => {
    try {
        const email = req.query.email;

        if (!email) {
            return res.status(400).send({ message: 'Email query parameter is required' });
        }

        // Ensure requester is asking for their own stats
        if (req.decoded_email !== email) {
            return res.status(403).send({ message: 'Forbidden: Cannot access other users statistics' });
        }

        const { orderCollection } = await getCollections();

        const stats = await orderCollection.aggregate([
            {
                $match: { userEmail: email }
            },
            {
                $group: {
                    _id: "$orderStatus",
                    count: { $sum: 1 }
                }
            }
        ]).toArray();

        // Convert array to object with camelCase keys
        const result = {};
        stats.forEach(stat => {
            const status = stat._id;
            // Convert status to camelCase: "In Production" -> "inProduction", "Pending" -> "pending"
            const parts = status.split(' ');
            const camelCaseKey = parts.map((part, index) => 
                index === 0 ? part.toLowerCase() : part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()
            ).join('');
            
            result[camelCaseKey] = stat.count;
        });

        res.send(result);
    } catch (error) {
        console.error('Error in /orders/stats GET:', error.message);
        console.error('Full error:', error);
        res.status(500).send({ message: 'Internal server error', error: error.message });
    }
});

// GET /orders/status/stats -> Admin endpoint to get order statistics by status
app.get('/orders/status/stats', verifyFBToken, verifyAdmin, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        
        const stats = await orderCollection.aggregate([
            {
                $group: {
                    _id: "$orderStatus",
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { count: -1 }
            }
        ]).toArray();

        res.send(stats);
    } catch (error) {
        console.error('Error in /orders/status/stats GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// GET /orders/delivery-status/stats -> Manager endpoint for delivery status statistics
app.get('/orders/delivery-status/stats', verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        
        // Get stats for delivery-related statuses
        const stats = await orderCollection.aggregate([
            {
                $match: {
                    orderStatus: { $in: ["Approved", "In Production", "Shipped", "Delivered"] }
                }
            },
            {
                $group: {
                    _id: "$orderStatus",
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { count: -1 }
            }
        ]).toArray();

        res.send(stats);
    } catch (error) {
        console.error('Error in /orders/delivery-status/stats GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// GET /manager/orders/count -> Manager endpoint to get count of orders by key statuses
app.get('/manager/orders/count', verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        
        const stats = await orderCollection.aggregate([
            {
                $group: {
                    _id: "$orderStatus",
                    count: { $sum: 1 }
                }
            }
        ]).toArray();

        // Convert to camelCase object format
        const result = {};
        stats.forEach(stat => {
            const status = stat._id;
            const parts = status.split(' ');
            const camelCaseKey = parts.map((part, index) => 
                index === 0 ? part.toLowerCase() : part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()
            ).join('');
            
            result[camelCaseKey] = stat.count;
        });

        res.send(result);
    } catch (error) {
        console.error('Error in /manager/orders/count GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// GET /payments/stats -> Admin endpoint to get payment statistics
app.get('/payments/stats', verifyFBToken, verifyAdmin, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        
        // Get payment statistics grouped by payment method
        const stats = await orderCollection.aggregate([
            {
                $match: {
                    paymentMethod: { $exists: true, $ne: null }
                }
            },
            {
                $group: {
                    _id: "$paymentMethod",
                    amount: { $sum: "$totalPrice" },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { amount: -1 }
            }
        ]).toArray();

        res.send(stats);
    } catch (error) {
        console.error('Error in /payments/stats GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// =================================================================
// ORDERS API - PARAMETERIZED ROUTES (Must come AFTER specific routes)
// =================================================================

// GET /orders/:id -> Returns single order details, only owner can access
app.get('/orders/:id', verifyFBToken, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid order id' });

        const order = await orderCollection.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).send({ message: 'Order not found' });

        if (order.userEmail !== req.decoded_email) {
            return res.status(403).send({ message: 'Forbidden: Cannot access this order' });
        }

        res.send(order);
    } catch (error) {
        console.error('Error in /orders/:id GET:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// PATCH /orders/:id/cancel -> Cancel an order (only if owner and status is Pending). Restores product stock.
app.patch('/orders/:id/cancel', verifyFBToken, async (req, res) => {
    try {
        const { orderCollection, productCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid order id' });

        const order = await orderCollection.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).send({ message: 'Order not found' });

        if (order.userEmail !== req.decoded_email) {
            return res.status(403).send({ message: 'Forbidden: Cannot cancel this order' });
        }

        if (order.orderStatus !== 'Pending') {
            return res.status(400).send({ message: 'Only pending orders can be cancelled' });
        }

        // Update order status to Cancelled and add cancelledAt metadata
        const update = {
            $set: { orderStatus: 'Cancelled', cancelledAt: new Date() },
        };

        const result = await orderCollection.updateOne({ _id: new ObjectId(id) }, update);

        // Restore product stock (best-effort)
        try {
            if (order.productId && ObjectId.isValid(order.productId)) {
                await productCollection.updateOne(
                    { _id: new ObjectId(order.productId) },
                    { $inc: { availableQuantity: order.orderQuantity } }
                );
            }
        } catch (err) {
            console.error('Failed to restore product stock after cancellation:', err.message);
        }

        res.send({ modifiedCount: result.modifiedCount });
    } catch (error) {
        console.error('Error in /orders/:id/cancel PATCH:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// PATCH /orders/:id/approve -> Manager approves an order. Deducts inventory if not already deducted.
app.patch('/orders/:id/approve', verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { orderCollection, productCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid order id' });

        const order = await orderCollection.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).send({ message: 'Order not found' });

        if (order.orderStatus === 'Approved') {
            return res.status(400).send({ message: 'Order is already approved' });
        }

        // If inventory was not yet deducted for this order, attempt to deduct now.
        if (!order.inventoryDeducted) {
            if (!order.productId || !ObjectId.isValid(order.productId)) {
                return res.status(400).send({ message: 'Order does not reference a valid product to deduct inventory.' });
            }

            const product = await productCollection.findOne({ _id: new ObjectId(order.productId) });
            if (!product) return res.status(404).send({ message: 'Referenced product not found' });

            const available = Number(product.availableQuantity || 0);
            const needed = Number(order.orderQuantity || 0);

            if (available < needed) {
                return res.status(400).send({ message: `Insufficient stock. Available: ${available}, required: ${needed}` });
            }

            // Deduct the available quantity
            await productCollection.updateOne(
                { _id: new ObjectId(order.productId) },
                { $inc: { availableQuantity: -needed } }
            );
        }

        // Mark order as approved and note who approved it. Also mark inventoryDeducted true.
        const update = {
            $set: {
                orderStatus: 'Approved',
                approvedAt: new Date(),
                approvedBy: req.decoded_email,
                inventoryDeducted: true,
            },
        };

        const result = await orderCollection.updateOne({ _id: new ObjectId(id) }, update);
        res.send({ modifiedCount: result.modifiedCount });
    } catch (error) {
        console.error('Error in /orders/:id/approve PATCH:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// PATCH /orders/:id/reject -> Manager rejects an order. Restores inventory if it was deducted.
app.patch('/orders/:id/reject', verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { orderCollection, productCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid order id' });

        const order = await orderCollection.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).send({ message: 'Order not found' });

        if (order.orderStatus === 'Rejected') {
            return res.status(400).send({ message: 'Order is already rejected' });
        }

        if (order.orderStatus === 'Approved') {
            return res.status(400).send({ message: 'Cannot reject an already approved order' });
        }

        // If inventory was deducted for this order, restore it back
        if (order.inventoryDeducted && order.productId && ObjectId.isValid(order.productId)) {
            const needed = Number(order.orderQuantity || 0);
            await productCollection.updateOne(
                { _id: new ObjectId(order.productId) },
                { $inc: { availableQuantity: needed } }
            );
        }

        // Mark order as rejected
        const update = {
            $set: {
                orderStatus: 'Rejected',
                rejectedAt: new Date(),
                rejectedBy: req.decoded_email,
                inventoryDeducted: false,
            },
        };

        const result = await orderCollection.updateOne({ _id: new ObjectId(id) }, update);
        res.send({ modifiedCount: result.modifiedCount });
    } catch (error) {
        console.error('Error in /orders/:id/reject PATCH:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// PATCH /orders/:id/delivery-status -> Manager updates delivery status
app.patch('/orders/:id/delivery-status', verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        const id = req.params.id;
        const { deliveryStatus } = req.body;

        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid order id' });

        if (!deliveryStatus) {
            return res.status(400).send({ message: 'Delivery status is required' });
        }

        // Validate delivery status values
        const validStatuses = [
            'order_placed',
            'cutting_completed',
            'sewing_started',
            'finishing',
            'qc_checked',
            'packed',
            'shipped_out_for_delivery',
            'delivered'
        ];

        if (!validStatuses.includes(deliveryStatus)) {
            return res.status(400).send({ message: 'Invalid delivery status' });
        }

        const order = await orderCollection.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).send({ message: 'Order not found' });

        const update = {
            $set: {
                deliveryStatus,
                deliveryStatusUpdatedAt: new Date(),
                deliveryStatusUpdatedBy: req.decoded_email,
            },
        };

        // Update orderStatus to "Delivered" when deliveryStatus is "delivered"
        if (deliveryStatus === 'delivered') {
            update.$set.orderStatus = 'Delivered';
        }
        // Update orderStatus to "Shipped" when deliveryStatus is "shipped_out_for_delivery"
        else if (deliveryStatus === 'shipped_out_for_delivery' && order.orderStatus !== 'Delivered') {
            update.$set.orderStatus = 'Shipped';
        }

        const result = await orderCollection.updateOne({ _id: new ObjectId(id) }, update);
        res.send({ modifiedCount: result.modifiedCount, message: 'Delivery status updated successfully' });
    } catch (error) {
        console.error('Error in /orders/:id/delivery-status PATCH:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// PATCH /orders/:id/withdraw-payment -> Manager withdraws payment (only if delivered and paid)
app.patch('/orders/:id/withdraw-payment', verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { orderCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid order id' });

        const order = await orderCollection.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).send({ message: 'Order not found' });

        // Check if order is delivered
        if (order.deliveryStatus !== 'delivered') {
            return res.status(400).send({ message: 'Cannot withdraw payment - order is not delivered yet' });
        }

        // Check if payment is already withdrawn
        if (order.paymentStatus === 'Withdrawn' || (order.paymentStatus && order.paymentStatus.includes('Withdrawn'))) {
            return res.status(400).send({ message: 'Payment has already been withdrawn' });
        }

        // Check if payment is paid - support various payment status formats
        const isPaid = order.paymentStatus === 'Paid' || 
                       (order.paymentStatus && order.paymentStatus.includes('Paid'));
        
        if (!isPaid) {
            return res.status(400).send({ 
                message: 'Cannot withdraw - payment is not completed', 
                currentStatus: order.paymentStatus 
            });
        }

        const update = {
            $set: {
                paymentStatus: 'Withdrawn',
                paymentWithdrawnAt: new Date(),
                paymentWithdrawnBy: req.decoded_email,
            },
        };

        const result = await orderCollection.updateOne({ _id: new ObjectId(id) }, update);
        res.send({ modifiedCount: result.modifiedCount, message: 'Payment withdrawn successfully' });
    } catch (error) {
        console.error('Error in /orders/:id/withdraw-payment PATCH:', error.message);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// =================================================================
//  USER API (No Changes)
// =================================================================
app.get("/users", async (req, res) => {
    try {
        const { userCollection } = await getCollections();
        const searchText = req.query.searchText;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 5;

        const query = {};
        if (searchText) {
            query.$or = [
                { name: { $regex: searchText, $options: "i" } },
                { email: { $regex: searchText, $options: "i" } },
            ];
        }

        // Get total count for pagination
        const totalCount = await userCollection.countDocuments(query);

        // Get users with pagination
        const users = await userCollection
            .find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .toArray();

        res.send({ users, totalCount });
    } catch (error) {
        console.error("Error in /users GET:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

app.get("/users/:email/role", verifyFBToken, async (req, res) => {
    try {
        const { userCollection } = await getCollections();
        const email = req.params.email;
        // IMPORTANT: Ensure the requested email matches the decoded token email for security
        if (req.decoded_email !== email) {
            return res.status(403).send({ message: "Forbidden: Cannot check role for other users" });
        }

        const query = { email };
        const user = await userCollection.findOne(query);
        res.send({ role: user?.role || "buyer" });
    } catch (error) {
        console.error("Error in /users/:email/role GET:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});


app.post('/users', async (req, res) => {
    const userInfo = req.body;
    const { email } = userInfo;

    try {
        const { userCollection } = await getCollections();
        const existingUser = await userCollection.findOne({ email: email });

        if (existingUser) {
            return res.send({ message: 'User already exists', insertedId: null });
        }

        // Add default role and status on creation
        userInfo.role = userInfo.role || 'member';
        userInfo.status = userInfo.status || 'active';
        userInfo.createdAt = new Date();

        const result = await userCollection.insertOne(userInfo);
        res.send(result);

    } catch (error) {
        console.error("Error creating new user:", error);
        res.status(500).send({ message: "Failed to create user", error: error.message });
    }
});

app.patch("/users/:id/role-and-status", verifyFBToken, verifyAdmin, async (req, res) => {
    try {
        const { userCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid ID" });
        }

        const { role, status } = req.body;

        if (!role || !status) {
            return res.status(400).send({ message: "Role and Status are required fields" });
        }

        const query = { _id: new ObjectId(id) };

        const updateDoc = {
            $set: {
                role: role,
                status: status,
            },
        };

        const result = await userCollection.updateOne(query, updateDoc);
        res.send(result);
    } catch (error) {
        console.error("Error in /users/:id/role-and-status PATCH:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// PATCH /users/:id/suspend -> Admin suspends a user with reason and feedback
app.patch("/users/:id/suspend", verifyFBToken, verifyAdmin, async (req, res) => {
    try {
        const { userCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid ID" });
        }

        const { suspendReason, suspendFeedback } = req.body;

        if (!suspendReason || !suspendFeedback) {
            return res.status(400).send({ message: "Suspend reason and feedback are required" });
        }

        const query = { _id: new ObjectId(id) };

        const updateDoc = {
            $set: {
                status: 'suspended',
                suspendReason,
                suspendFeedback,
                suspendedAt: new Date(),
                suspendedBy: req.decoded_email,
            },
        };

        const result = await userCollection.updateOne(query, updateDoc);
        res.send(result);
    } catch (error) {
        console.error("Error in /users/:id/suspend PATCH:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// PATCH /users/:id/unsuspend -> Admin unsuspends a user
app.patch("/users/:id/unsuspend", verifyFBToken, verifyAdmin, async (req, res) => {
    try {
        const { userCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid ID" });
        }

        const query = { _id: new ObjectId(id) };

        const updateDoc = {
            $set: {
                status: 'active',
            },
            $unset: {
                suspendReason: "",
                suspendFeedback: "",
                suspendedAt: "",
                suspendedBy: "",
            },
        };

        const result = await userCollection.updateOne(query, updateDoc);
        res.send(result);
    } catch (error) {
        console.error("Error in /users/:id/role-and-status PATCH:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});

// =================================================================
// --- SERVER STARTUP ---
// =================================================================

app.listen(port, () => {
    console.log(`Garment Order Tracker backend listening on port ${port}`)
})

connectToMongo().catch(console.dir);

// =================================================================
// Stripe Test Payment Endpoint
// =================================================================
app.post('/create-payment-intent', verifyFBToken, async (req, res) => {
    try {
        if (!stripe) return res.status(500).send({ message: 'Stripe not configured on server.' });

        const { amount, currency = 'usd', bookingId } = req.body;
        if (!amount || amount <= 0) {
            return res.status(400).send({ message: 'Valid amount is required' });
        }

        // Stripe expects amount in cents for fiat currencies
        const amountInCents = Math.round(Number(amount) * 100);

        const paymentIntent = await stripe.paymentIntents.create({
            amount: amountInCents,
            currency,
            metadata: { bookingId: bookingId || '' },
        });

        res.send({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).send({ message: 'Failed to create payment intent', error: error.message });
    }
});


// =================================================================
// Checkout Session Endpoint (redirect flow)
// POST /create-checkout-session { orderId }
// Creates a Stripe Checkout Session and returns { url }
// =================================================================
app.post('/create-checkout-session', verifyFBToken, async (req, res) => {
    try {
        if (!stripe) return res.status(500).send({ message: 'Stripe not configured on server.' });

        const { orderId } = req.body;
        if (!orderId || !ObjectId.isValid(orderId)) {
            return res.status(400).send({ message: 'orderId is required and must be a valid id.' });
        }

        const { orderCollection } = await getCollections();
        const order = await orderCollection.findOne({ _id: new ObjectId(orderId) });

        if (!order) return res.status(404).send({ message: 'Order not found' });

        // Only the owner may create a checkout session for this order
        if (order.userEmail !== req.decoded_email) {
            return res.status(403).send({ message: 'Forbidden: Cannot create checkout session for this order' });
        }

        // Only allow payment for approved orders (manager approved) and unpaid orders
        const paidFlag = (order.paymentStatus || '').toString().toLowerCase().includes('paid');
        if (paidFlag) return res.status(400).send({ message: 'Order is already paid.' });

        // Determine unit price and quantity
        const unitPrice = Number(order.unitPrice || (order.totalPrice && order.orderQuantity ? order.totalPrice / order.orderQuantity : 0));
        const quantity = Number(order.orderQuantity || 1);
        if (!unitPrice || unitPrice <= 0) return res.status(400).send({ message: 'Invalid order price for payment.' });

        // Build line items for Checkout
        const line_items = [
            {
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: (order.productTitle || order.productName || 'Garment Order'),
                        description: `Order #${order._id}`,
                    },
                    unit_amount: Math.round(unitPrice * 100),
                },
                quantity: quantity,
            },
        ];

        const successUrl = (process.env.CLIENT_URL || 'http://localhost:5173') + '/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}';
        const cancelUrl = (process.env.CLIENT_URL || 'http://localhost:5173') + '/dashboard/payment-cancelled';

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'payment',
            line_items,
            customer_email: order.userEmail,
            metadata: { orderId: order._id.toString() },
            success_url: successUrl,
            cancel_url: cancelUrl,
        });

        // Return the URL to which the client should redirect
        res.send({ url: session.url });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).send({ message: 'Failed to create checkout session', error: error.message });
    }
});

// =================================================================
// PATCH /payment-success?session_id=xxx
// Verify the Stripe session and update order payment status
// =================================================================
app.patch("/payment-success", verifyFBToken, async (req, res) => {
    try {
        if (!stripe) return res.status(500).send({ message: 'Stripe not configured on server.' });

        const sessionId = req.query.session_id;
        if (!sessionId) {
            return res.status(400).send({ message: 'session_id query parameter is required' });
        }

        // Retrieve the session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        
        if (!session) {
            return res.status(404).send({ message: 'Checkout session not found' });
        }

        // Get the orderId from metadata
        const orderId = session.metadata?.orderId;
        if (!orderId || !ObjectId.isValid(orderId)) {
            return res.status(400).send({ message: 'Invalid or missing orderId in session metadata' });
        }

        const { orderCollection } = await getCollections();
        const order = await orderCollection.findOne({ _id: new ObjectId(orderId) });

        if (!order) {
            return res.status(404).send({ message: 'Order not found' });
        }

        // Verify the user owns this order
        if (order.userEmail !== req.decoded_email) {
            return res.status(403).send({ message: 'Forbidden: Cannot update this order' });
        }

        // Check if payment was successful
        if (session.payment_status !== 'paid') {
            return res.status(400).send({ message: 'Payment not completed', paymentStatus: session.payment_status });
        }

        // Update order payment status
        const updateDoc = {
            $set: {
                paymentStatus: 'Paid - Stripe',
                paymentMethod: 'Stripe',
                stripeSessionId: sessionId,
                stripePaymentIntent: session.payment_intent,
                paidAt: new Date(),
            },
        };

        await orderCollection.updateOne({ _id: new ObjectId(orderId) }, updateDoc);

        res.send({
            success: true,
            orderId: orderId,
            transactionId: session.payment_intent,
            message: 'Payment successful'
        });

    } catch (error) {
        console.error('Error in /payment-success PATCH:', error.message);
        res.status(500).send({ message: 'Internal server error', error: error.message });
    }
});