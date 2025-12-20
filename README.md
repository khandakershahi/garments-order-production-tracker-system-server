# Garments Order Production Tracker System - Server

Backend API for the Garments Order Production Tracker System. This Express.js server handles authentication, user management, product management, order processing, and provides secure endpoints for the client application.

## Features

### Authentication & Authorization
- Firebase Admin SDK integration for token verification
- JWT-based authentication middleware
- Role-based access control (Admin, Manager, Buyer)
- Secure cookie handling

### User Management
- User registration and profile management
- Role assignment and updates
- Account suspension functionality
- User status tracking

### Product Management
- CRUD operations for products
- Search products by name
- Filter by category
- Pagination support
- Image URL storage (feature image + multiple images)
- Toggle product visibility on homepage
- Product availability tracking

### Order Management
- Create, update, and track orders
- Order status management (Pending, Approved, In Production, Shipped, Delivered)
- Order rejection with reasons
- District-wise delivery tracking
- Order filtering by status and buyer
- Order history and statistics

### Feedback System
- Product feedback and ratings
- User feedback management
- Feedback retrieval by product

### Statistics & Analytics
- User count by role
- Order statistics
- Product metrics
- Dashboard analytics

## Technologies

### Core
- **Node.js** v18+ - JavaScript runtime
- **Express.js** v4.21.2 - Web framework
- **MongoDB** v6.12.0 - Database
- **Mongoose** (optional) - ODM for MongoDB

### Authentication
- **Firebase Admin SDK** v13.0.3 - Authentication verification
- **Cookie Parser** v1.4.7 - Cookie parsing middleware

### Security
- **CORS** v2.8.5 - Cross-origin resource sharing
- **dotenv** v16.4.7 - Environment variable management

### Development
- **Nodemon** v3.1.9 - Auto-restart during development

## Environment Variables

Create a `.env` file in the root directory:

```env
PORT=5000
DB_USER=your_mongodb_username
DB_PASS=your_mongodb_password
NODE_ENV=production
COOKIE_SECRET=your_cookie_secret_key
```

Also required:
- `garments-firebase-adminsdk.json` - Firebase Admin SDK service account key file

## Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/garments-order-production-tracker-system-server.git
   cd garments-order-production-tracker-system-server
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   - Create a `.env` file in the root directory
   - Add all required environment variables (see above)
   - Place Firebase Admin SDK JSON file in the root directory

4. **Start development server**
   ```bash
   npm run dev
   ```
   
   Server will run on `http://localhost:5000`

5. **Start production server**
   ```bash
   npm start
   ```

## API Endpoints

### Authentication
- `POST /jwt` - Generate JWT token
- `POST /logout` - Clear authentication cookie

### Users
- `GET /users` - Get all users (Admin only)
- `GET /users/email/:email` - Get user by email
- `POST /users` - Create new user
- `PATCH /users/:id` - Update user (role, status)

### Products
- `GET /products` - Get all products (with search, filter, pagination)
- `GET /products/:id` - Get single product
- `POST /products` - Create product (Manager/Admin)
- `PUT /products/:id` - Update product (Manager/Admin)
- `PATCH /products/:id` - Update product fields (show on home, etc.)
- `DELETE /products/:id` - Delete product (Manager/Admin)

### Orders
- `GET /orders` - Get all orders (Admin/Manager)
- `GET /orders/buyer/:email` - Get orders by buyer email
- `GET /orders/:id` - Get single order
- `POST /orders` - Create new order (Buyer)
- `PATCH /orders/:id` - Update order status
- `PATCH /orders/:id/reject` - Reject order with reason
- `DELETE /orders/:id` - Delete order

### Feedbacks
- `GET /feedbacks` - Get all feedbacks
- `GET /feedbacks/product/:productId` - Get feedbacks by product
- `POST /feedbacks` - Create feedback
- `DELETE /feedbacks/:id` - Delete feedback

### Statistics
- `GET /stats/users` - Get user count by role
- `GET /stats/orders` - Get order statistics
- `GET /stats/products` - Get product metrics

## Database Schema

### Users Collection
```javascript
{
  name: String,
  email: String (unique),
  role: String (enum: ['buyer', 'manager', 'admin']),
  photoURL: String,
  status: String (enum: ['active', 'suspended']),
  createdAt: Date
}
```

### Products Collection
```javascript
{
  productName: String,
  description: String,
  category: String,
  price: Number,
  availableQuantity: Number,
  minOrderQuantity: Number,
  featureImage: String,
  images: [String],
  videoLink: String,
  paymentOption: String,
  showInHeroSlider: Boolean,
  showOnHomePage: Boolean,
  createdAt: Date,
  updatedAt: Date
}
```

### Orders Collection
```javascript
{
  buyerEmail: String,
  buyerName: String,
  productId: ObjectId,
  productName: String,
  productImage: String,
  quantity: Number,
  price: Number,
  totalAmount: Number,
  paymentOption: String,
  deliveryDistrict: String,
  deliveryAddress: String,
  phoneNumber: String,
  status: String (enum: ['pending', 'approved', 'rejected', 'in-production', 'shipped', 'delivered']),
  rejectionReason: String,
  createdAt: Date,
  updatedAt: Date
}
```

### Feedbacks Collection
```javascript
{
  productId: ObjectId,
  userEmail: String,
  userName: String,
  userPhoto: String,
  rating: Number (1-5),
  comment: String,
  createdAt: Date
}
```

## Middleware

### verifyToken
Validates Firebase JWT tokens from cookies and attaches user email to request object.

### verifyAdmin
Ensures the authenticated user has admin role.

### verifyManager
Ensures the authenticated user has manager or admin role.

## Error Handling

The server implements comprehensive error handling:
- Validation errors
- Authentication errors
- Authorization errors
- Database errors
- 404 Not Found errors

## Security Features

- Firebase Admin SDK for secure authentication
- HTTP-only cookies for token storage
- CORS configuration for client-server communication
- Environment-based configuration
- Role-based access control
- Input validation

## Available Scripts

- `npm start` - Start production server
- `npm run dev` - Start development server with nodemon

## Deployment

### Vercel Deployment
1. Install Vercel CLI: `npm i -g vercel`
2. Create `vercel.json` configuration
3. Deploy: `vercel --prod`

### Environment Variables on Vercel
Set these in Vercel dashboard:
- `DB_USER`
- `DB_PASS`
- `NODE_ENV`
- `COOKIE_SECRET`

Upload Firebase Admin SDK JSON via Vercel dashboard.

## Database Setup

### MongoDB Atlas
1. Create a MongoDB Atlas cluster
2. Create database: `garmentsOrderTracker`
3. Collections will be created automatically:
   - `users`
   - `products`
   - `orders`
   - `feedbacks`
4. Add your IP to whitelist or allow all IPs (0.0.0.0/0)

## Firebase Admin Setup

1. Go to Firebase Console
2. Project Settings > Service Accounts
3. Generate new private key
4. Save as `garments-firebase-adminsdk.json` in server root
5. Never commit this file to version control

## Performance Optimization

- Database indexing on frequently queried fields
- Pagination for large datasets
- Efficient query projection
- Connection pooling

## Testing

Test API endpoints using:
- Postman
- Thunder Client (VS Code extension)
- curl commands

Example test:
```bash
curl -X GET http://localhost:5000/products
```

## Contributing

This is an educational project. Contributions, issues, and feature requests are welcome!

## License

This project is for educational purposes as part of Programming Hero curriculum.

## Support

For issues or questions, please create an issue in the GitHub repository.

---

**Note**: Ensure MongoDB connection is established before starting the server. Check console for connection success message.
