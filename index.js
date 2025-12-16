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
const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
let stripe = null;
if (stripeSecret) {
    stripe = new Stripe(stripeSecret, { apiVersion: '2023-08-16' });
} else {
    console.warn('STRIPE_SECRET_KEY not set. Stripe routes will fail until configured.');
}

// --- Firebase Initialization ---
const admin = require("firebase-admin");
const serviceAccount = require("./garments-firebase-adminsdk.json");
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
// Configure CORS to explicitly allow the frontend URL and enable credentials
const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
const corsOptions = {
    origin: clientUrl,
    methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
    // include any custom headers your client may send (e.g. X-Custom-Header)
    allowedHeaders: ['Content-Type','Authorization','X-Requested-With','X-Custom-Header'],
    credentials: true,
    optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));


// =================================================================
// --- AUTHENTICATION & AUTHORIZATION MIDDLEWARE ---
// =================================================================

const verifyFBToken = async (req, res, next) => {
    console.log("header in the middleware", req.headers?.authorization);
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send({ message: "Unauthorized access" });
    }
    try {
        const idToken = token.split(" ")[1];
        const decoded = await admin.auth().verifyIdToken(idToken);
        console.log("decoded token", decoded);
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
    };
};

// =================================================================
// --- BASE ROUTE ---
// =================================================================

app.get('/', (req, res) => {
    res.send('Garment Order Production Tracker is running')
})


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
// ⭐ SINGLE PRODUCT API: GET /products/:id ⭐
// =================================================================

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


// Updated Backend Route: /products (replace the existing GET /products in your server code)

app.get('/products', async (req, res) => {
    try {
        const { productCollection } = await getCollections();

        // Simple product list endpoint. Optional `limit` query param (number of items to return).
        const limit = parseInt(req.query.limit) || 9;

        const products = await productCollection
            .find({})
            .sort({ createdAt: -1 })
            .limit(limit)
            .toArray();

        res.send({ products });
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


// =================================================================
//  USER API (No Changes)
// =================================================================
app.get("/users", async (req, res) => {
    try {
        const { userCollection } = await getCollections();
        const searchText = req.query.searchText;
        const query = {};
        if (searchText) {
            query.$or = [
                { name: { $regex: searchText, $options: "i" } },
                { email: { $regex: searchText, $options: "i" } },
            ];
        }

        const cursor = userCollection.find(query).sort({ createdAt: -1 }).limit(5);
        const result = await cursor.toArray();
        res.send(result);
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
// POST /create-payment-intent { amount: number, currency?: string, bookingId?: string }
app.post('/create-payment-intent', verifyFBToken, async (req, res) => {
    try {
        if (!stripe) return res.status(500).send({ message: 'Stripe not configured on server.' });

        const { amount, currency = 'usd', bookingId } = req.body;
        if (!amount || isNaN(amount) || amount <= 0) {
            return res.status(400).send({ message: 'Invalid amount. Amount must be a positive number.' });
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