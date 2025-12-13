const express = require('express');
const app = express();
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require("dotenv").config();
const crypto = require('crypto');
// Note: Port is removed as Vercel handles this
const port = process.env.PORT || 3000;

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
app.use(cors());


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
app.get("/products", async (req, res) => {
    try {
        const { productCollection } = await getCollections();
        const { searchText, category, showOnHomePage, managerEmail, limit } = req.query;
        const query = {};

        // 1. Search Text (Search by title or description)
        if (searchText) {
            query.$or = [
                { title: { $regex: searchText, $options: "i" } },
                { description: { $regex: searchText, $options: "i" } },
            ];
        }

        // 2. Category Filter
        if (category) {
            query.category = category;
        }

        // 3. Homepage Filter (For the main Home page section)
        if (showOnHomePage === 'true') {
            query.showOnHomePage = true;
        }

        // 4. Manager Filter (For the Manager's /dashboard/manage-products page)
        if (managerEmail) {
            query.managerEmail = managerEmail;
        }

        let queryLimit = parseInt(limit) || 200; // Default limit

        const products = await productCollection
            .find(query)
            .sort({ createdAt: -1 })
            .limit(queryLimit)
            .toArray();

        res.send(products);
    } catch (error) {
        console.error("Error in /products GET:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});


// POST /products: Used by Manager to add new products (Secured)
app.post("/products", verifyFBToken, verifyManager, async (req, res) => {
    try {
        const { productCollection } = await getCollections();
        let productInfo = req.body;

        // 1. Generate and attach the unique product ID
        const uniqueProductId = generateProductId();
        productInfo.productId = uniqueProductId;

        // 2. Attach the manager's email from the verified token payload (Security/Ownership)
        productInfo.managerEmail = req.decoded_email;
        productInfo.createdAt = new Date(); // Add creation timestamp

        // 3. Insert the new product
        const result = await productCollection.insertOne(productInfo);

        // 4. Send the result back, optionally including the generated ID
        res.send({ ...result, productId: uniqueProductId });
    } catch (error) {
        console.error("Error in /products POST:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});


// GET /products/:id: Retrieves a specific product for ordering (Secured: Logged-in User Access)
app.get("/products/:id", verifyFBToken, async (req, res) => {
    try {
        const { productCollection } = await getCollections();
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid Product ID format" });
        }

        const query = { _id: new ObjectId(id) };
        const product = await productCollection.findOne(query);

        if (!product) {
            return res.status(404).send({ message: "Product not found" });
        }

        // Convert ObjectId to string for client-side use
        product._id = product._id.toString();

        res.send(product);
    } catch (error) {
        console.error("Error in /products/:id GET for members:", error.message);
        res.status(500).send({ message: "Internal server error" });
    }
});


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