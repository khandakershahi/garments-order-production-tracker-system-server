const express = require('express')
const app = express();
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require('mongodb');
require("dotenv").config();
// Note: Port is removed as Vercel handles this
const port = process.env.PORT || 3000;

// middleware
app.use(express.json());
app.use(cors());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.7c8ysvf.mongodb.net/?appName=Cluster0`;

// Create a MongoClient outside the connection function (Global)
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }, // Added timeouts for better serverless performance
    connectTimeoutMS: 10000,
    socketTimeoutMS: 10000,
});





// --- 2. Centralized MongoDB Connection/Initialization Function ---
async function connectToMongo() {
    try {
        // Check if the client is already connected or connecting
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

// Helper function to get collections inside any route/middleware that needs them
const getCollections = async () => {
    const db = await connectToMongo();
    return {
        userCollection: db.collection("users"),
        // ... potentially other collections
    };
};

// all routes

app.get("/users", (req, res) => {

    res.send("Garment Production Tracker is running");
});

// =================================================================
// ⭐ USER API (NEW)
// =================================================================

app.post('/users', async (req, res) => {
    // 1. Get the user data from the client (from Register.jsx component)
    const userInfo = req.body;
    const { email } = userInfo;

    try {
        const { userCollection } = await getCollections();

        // 2. Check if a user with this email already exists
        const existingUser = await userCollection.findOne({ email: email });

        if (existingUser) {
            // Return a status code indicating that the resource already exists
            return res.send({ message: 'User already exists', insertedId: null });
        }

        // 3. Insert the new user into the database
        // The userInfo object now contains: { email, name, photoURL, role, status: "pending" }
        const result = await userCollection.insertOne(userInfo);

        // 4. Send the result back to the client
        res.send(result);

    } catch (error) {
        console.error("Error creating new user:", error);
        // Send a 500 status code for internal server errors
        res.status(500).send({ message: "Failed to create user", error: error.message });
    }
});





app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})


connectToMongo().catch(console.dir);


// --- 5. Export for Vercel ---
// module.exports = app;