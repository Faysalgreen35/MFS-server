const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.5ynzghe.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();
    const userCollection = client.db("MFSDb").collection("users");
    const cashInRequestCollection = client.db("MFSDb").collection("cashIn");
    const cashOutRequestCollection = client.db("MFSDb").collection("cashOut");
    const transactionCollection = client.db("MFSDb").collection("transactions");

    // JWT Generation
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1d" });
      res.send({ token });
    });

    // Middleware to verify token
    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).send({ message: 'forbidden access' });
      }
      const token = authHeader.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'forbidden access' });
        }
        req.decoded = decoded;
        next();
      });
    };

    // Middleware to verify roles
    const verifyRole = (role) => async (req, res, next) => {
      const email = req.decoded.email;
      const user = await userCollection.findOne({ email });
      if (!user || user.role !== role) {
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    };

    // Endpoint to get user details based on token
    app.get('/user', verifyToken, async (req, res) => {
      try {
        const userId = new ObjectId(req.decoded.userId);
        const user = await userCollection.findOne({ _id: userId }, { projection: { pin: 0 } }); // Exclude PIN from the response

        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }

        res.json({ user });
      } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });

    // Endpoint to get user's role by email
    app.get('/users/role/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      try {
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send({ role: user.role });
      } catch (error) {
        console.error('Error fetching user role', error);
        res.status(500).send({ message: 'Internal server error' });
      }
    });

    // Get all users
    app.get('/all-user', verifyToken, verifyRole('admin'), async (req, res) => {
      try {
        const users = await userCollection.find().sort({ timestamp: -1 }).toArray();


        const enrichedRequests = await Promise.all(users.map(async (user) => {
          return {
            ...user,

          };
        }));

        res.json(enrichedRequests);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // User approve
    app.post('/user/approve', verifyToken, verifyRole('admin'), async (req, res) => {
      const { requestId } = req.body;

      try {
        const request = await userCollection.findOne({ _id: new ObjectId(requestId) });
        if (!request || request.status !== 'pending') return res.status(400).json({ message: 'Invalid or already processed request' });

        const user = await userCollection.findOne({ _id: new ObjectId(request._id) });

        // Update user's balance with 40 Taka bonus
        user.balance += 40;

        // If the user is an agent, also update the agent's balance with 10,000 Taka bonus
        if (user.role === 'agent') {
          user.balance += 10000;
        }

        // Update user status to 'active'
        await userCollection.updateOne({ _id: user._id }, { $set: { balance: user.balance, status: 'active' } });

        // Record transaction for the bonus
        const transaction = {
          userId: user._id,
          amount: 40,
          type: 'bonus',
          timestamp: new Date()
        };

        // Record agent's bonus transaction if applicable
        if (user.role === 'agent') {
          transaction.amount += 10000;
        }

        await transactionCollection.insertOne(transaction);

        res.json({ message: 'User approved successfully' });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // User Registration
    app.post('/register', async (req, res) => {
      const { name, pin, mobileNumber, email, role = 'user' } = req.body;
      const hashedPin = await bcrypt.hash(pin, 10);
      const newUser = { name, pin: hashedPin, mobileNumber, email, role, status: 'pending', balance: 0 };
      const result = await userCollection.insertOne(newUser);
      res.status(201).send(result);
    });

    // User Login
    app.post('/login', async (req, res) => {
      const { emailOrPhone, pin } = req.body;

      // Determine if the input is an email or a phone number
      const query = emailOrPhone.includes('@') ? { email: emailOrPhone } : { mobileNumber: emailOrPhone };

      try {
        const user = await userCollection.findOne(query);
        if (!user) {
          return res.status(401).send({ message: 'Invalid credentials' });
        }

        const isPinValid = await bcrypt.compare(pin, user.pin);
        if (!isPinValid) {
          return res.status(401).send({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
          { userId: user._id, email: user.email, role: user.role },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: '1d' }
        );

        res.send({ token, user });
      } catch (error) {
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    // User Activation by Admin
    app.patch('/users/activate/:id', verifyToken, verifyRole('admin'), async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          status: 'active',
          balance: 40 // credit bonus
        }
      };
      const result = await userCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Check if user is an admin
    app.get('/users/admin/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'unauthorized access' });
      }
      const user = await userCollection.findOne({ email });
      const isAdmin = user && user.role === 'admin';
      res.send({ admin: isAdmin });
    });

    // Get all users
    app.get('/users', verifyToken, verifyRole('admin'), async (req, res) => {
      const users = await userCollection.find().toArray();
      res.send(users);
    });

    // Make user admin
    app.patch('/users/admin/:id', verifyToken, verifyRole('admin'), async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          role: 'admin'
        }
      };
      const result = await userCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Make user agent
    app.patch('/users/agent/:id', verifyToken, verifyRole('admin'), async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          role: 'agent'
        }
      };
      const result = await userCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Delete user
    app.delete('/users/:id', verifyToken, verifyRole('admin'), async (req, res) => {
      const id = req.params.id;
      try {
        const result = await userCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 1) {
          res.status(200).json({ message: 'User deleted successfully' });
        } else {
          res.status(404).json({ message: 'User not found' });
        }
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });




    // Send Money

    app.post('/send', verifyToken, verifyRole('user'), async (req, res) => {
      const { recipientMobile, amount, pin } = req.body;

      try {
        // Validate minimum transaction amount
        if (amount < 50) {
          return res.status(400).json({ message: 'Minimum transaction amount is 50 Taka' });
        }

        // Fetch sender's information
        const sender = await userCollection.findOne({ _id: new ObjectId(req.decoded.userId) });
        if (!sender) {
          return res.status(400).json({ message: 'Sender not found' });
        }

        // Fetch recipient's information
        const recipient = await userCollection.findOne({ mobileNumber: recipientMobile });
        if (!recipient) {
          return res.status(400).json({ message: 'Recipient not found' });
        }

        // Verify PIN
        const isMatch = await bcrypt.compare(pin, sender.pin);
        if (!isMatch) {
          return res.status(400).json({ message: 'Invalid PIN' });
        }

        // Calculate fee
        let fee = 0;
        if (amount > 100) {
          fee = 5;
        }

        // Calculate total amount to deduct from sender
        const totalAmountToDeduct = amount + fee;

        // Check if sender has sufficient balance
        if (sender.balance < totalAmountToDeduct) {
          return res.status(400).json({ message: 'Insufficient balance' });
        }

        // Deduct amount from sender's balance
        sender.balance -= totalAmountToDeduct;

        // Add amount to recipient's balance
        recipient.balance += amount;

        // Update balances in the database
        await userCollection.updateOne({ _id: sender._id }, { $set: { balance: sender.balance } });
        await userCollection.updateOne({ _id: recipient._id }, { $set: { balance: recipient.balance } });

        // Record transaction
        const transaction = {
          senderId: sender._id,
          recipientId: recipient._id,
          amount,
          fee,
          type: 'send',
          timestamp: new Date()
        };
        await transactionCollection.insertOne(transaction);

        // Respond with success message
        res.json({ message: 'Transaction successful' });

      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // POST of cashout 
    app.post('/cashout-request', verifyToken, async (req, res) => {
      const { agentMobile, amount } = req.body;

      if (amount < 50) return res.status(400).json({ message: 'Minimum transaction amount is 50 Taka' });

      try {
        const user = await userCollection.findOne({ _id: new ObjectId(req.decoded.userId) });
        const agent = await userCollection.findOne({ mobileNumber: agentMobile });
        if (!agent) return res.status(400).json({ message: 'Agent not found' });

        // Record cash-in request
        const cashOutRequest = {
          userId: user._id,
          requesterMobile: user.mobileNumber,
          agentId: agent._id,
          agentMobile: agentMobile,
          amount,
          status: 'pending',
          timestamp: new Date()
        };
        await cashOutRequestCollection.insertOne(cashOutRequest);

        res.json({ message: 'Cash-in request sent successfully' });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Cash Out  all requests
    app.get('/cashout-requests', verifyToken, async (req, res) => {
      try {
        const userId = new ObjectId(req.decoded.userId);
        const userRole = req.decoded.role;

        // Fetch cash-in requests made by the user or for the agent
        const query = userRole === 'agent' ? { agentId: userId } : { requesterId: userId };
        const cashOutRequests = await cashOutRequestCollection
          .find(query)
          .sort({ timestamp: -1 })
          .toArray();

        // Include the requester's mobile number
        const enrichedRequests = await Promise.all(cashOutRequests.map(async (request) => {
          const requester = await userCollection.findOne({ _id: new ObjectId(request.userId) });
          return {
            ...request,
            requesterMobile: requester?.mobileNumber
          };
        }));

        res.json(enrichedRequests);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.post('/cashout/approve', verifyToken, verifyRole('agent'), async (req, res) => {
      const { requestId } = req.body;

      try {
        const request = await cashOutRequestCollection.findOne({ _id: new ObjectId(requestId) });
        if (!request || request.status !== 'pending') return res.status(400).json({ message: 'Invalid or already processed request' });

        const user = await userCollection.findOne({ _id: new ObjectId(request.userId) });
        const agent = await userCollection.findOne({ _id: new ObjectId(request.agentId) });

        if (user.balance < request.amount) return res.status(400).json({ message: 'User has insufficient balance' });
        const fee = request.amount * 0.015; // 1.5% fee
        // user.balance = request.amount - fee ;
        // agent.balance = request.amount + fee;

        // Update balances
        const totalDeduction = request.amount + fee;
        user.balance -= totalDeduction;
        agent.balance += request.amount + fee;

        // Update balances
        await userCollection.updateOne({ _id: user._id }, { $set: { balance: user.balance } });
        await userCollection.updateOne({ _id: agent._id }, { $set: { balance: agent.balance } });

        // Update request status
        await cashOutRequestCollection.updateOne({ _id: request._id }, { $set: { status: 'approved' } });

        // Record transaction
        const transaction = {
          userId: user._id,
          agentId: agent._id,
          amount: request.amount,
          type: 'cashout',
          timestamp: new Date()
        };
        await transactionCollection.insertOne(transaction);

        res.json({ message: 'Cash-Out approved successfully' });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Endpoint to post user's cash-in requests
    app.post('/cashin-request', verifyToken, async (req, res) => {
      const { agentMobile, amount } = req.body;

      if (amount < 50) return res.status(400).json({ message: 'Minimum transaction amount is 50 Taka' });

      try {
        const user = await userCollection.findOne({ _id: new ObjectId(req.decoded.userId) });
        const agent = await userCollection.findOne({ mobileNumber: agentMobile });
        if (!agent) return res.status(400).json({ message: 'Agent not found' });

        // Record cash-in request
        const cashInRequest = {
          userId: user._id,
          requesterMobile: user.mobileNumber,
          agentId: agent._id,
          agentMobile: agentMobile,
          amount,
          status: 'pending',
          timestamp: new Date()
        };
        await cashInRequestCollection.insertOne(cashInRequest);

        res.json({ message: 'Cash-in request sent successfully' });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Combined Endpoint to get and approve cash-in requests
    app.get('/cashin-requests', verifyToken, async (req, res) => {
      try {
        const userId = new ObjectId(req.decoded.userId);
        const userRole = req.decoded.role;

        // Fetch cash-in requests made by the user or for the agent
        const query = userRole === 'agent' ? { agentId: userId } : { requesterId: userId };
        const cashInRequests = await cashInRequestCollection
          .find(query)
          .sort({ timestamp: -1 })
          .toArray();

        // Include the requester's mobile number
        const enrichedRequests = await Promise.all(cashInRequests.map(async (request) => {
          const requester = await userCollection.findOne({ _id: new ObjectId(request.userId) });
          return {
            ...request,
            requesterMobile: requester?.mobileNumber
          };
        }));

        res.json(enrichedRequests);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // approve cash in 
    app.post('/cashin/approve', verifyToken, verifyRole('agent'), async (req, res) => {
      const { requestId } = req.body;

      try {
        const request = await cashInRequestCollection.findOne({ _id: new ObjectId(requestId) });
        if (!request || request.status !== 'pending') return res.status(400).json({ message: 'Invalid or already processed request' });

        const user = await userCollection.findOne({ _id: new ObjectId(request.userId) });
        const agent = await userCollection.findOne({ _id: new ObjectId(request.agentId) });

        if (agent.balance < request.amount) return res.status(400).json({ message: 'Agent has insufficient balance' });

        user.balance += request.amount;
        agent.balance -= request.amount;

        // Update balances
        await userCollection.updateOne({ _id: user._id }, { $set: { balance: user.balance } });
        await userCollection.updateOne({ _id: agent._id }, { $set: { balance: agent.balance } });

        // Update request status
        await cashInRequestCollection.updateOne({ _id: request._id }, { $set: { status: 'approved' } });

        // Record transaction
        const transaction = {
          userId: user._id,
          agentId: agent._id,
          amount: request.amount,
          type: 'cashin',
          timestamp: new Date()
        };
        await transactionCollection.insertOne(transaction);

        res.json({ message: 'Cash-in approved successfully' });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });


    // Get User Balance
    // app.get('/balance', verifyToken, async (req, res) => {
    //   try {
    //     const user = await userCollection.findOne({ _id: new ObjectId(req.decoded.userId) }, { projection: { balance: 1 } });
    //     if (!user) return res.status(404).json({ message: 'User not found' });

    //     res.json({ balance: user.balance });
    //   } catch (error) {
    //     res.status(500).json({ message: error.message });
    //   }
    // });

    // Get User Balance
    app.get('/balance', verifyToken, async (req, res) => {
      try {
        const user = await userCollection.findOne(
          { _id: new ObjectId(req.decoded.userId) },
          { projection: { balance: 1, name: 1 } }
        );
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({ balance: user.balance, name: user.name });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });


    // Get User Transactions Including Send Money
    app.get('/transactions', verifyToken, async (req, res) => {
      try {
        const userId = new ObjectId(req.decoded.userId);

        // Fetch transactions for the user excluding 'cashin' requests where the user is the requester
        const transactions = await transactionCollection
          .find({
            $or: [
              { userId: userId },
              { agentId: userId },
              { recipientId: userId },
            ],
            $or: [
              { type: { $ne: 'cashin' } }, // Exclude all cashin transactions
              { requesterId: { $ne: userId } } // Exclude cashin requests made by the user
            ]
          })
          .sort({ timestamp: -1 })  // Sort by timestamp in descending order
          .limit(10)  // Limit to 10 most recent transactions
          .toArray();

        res.json(transactions);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });



    // Get User Transactions
    // app.get('/transactions', verifyToken, async (req, res) => {
    //   try {
    //     const transactions = await transactionCollection
    //       .find({ userId: new ObjectId(req.decoded.userId) })
    //       .sort({ timestamp: -1 })  // Sort by timestamp in descending order
    //       .toArray();
    //     res.json(transactions);
    //   } catch (error) {
    //     res.status(500).json({ message: error.message });
    //   }
    // });

    console.log("Connected to MongoDB!");

  } finally {
    // Ensure proper cleanup if needed
  }
}

run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('MFS server is running');
});

app.listen(port, () => {
  console.log(`MFS is sitting on port ${port}`);
});

// const express = require('express');
// const cors = require('cors');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// require('dotenv').config();

// const app = express();
// const port = process.env.PORT || 5000;

// // Middleware
// app.use(cors());
// app.use(express.json());

// const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.5ynzghe.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// const client = new MongoClient(uri, {
//   serverApi: {
//     version: ServerApiVersion.v1,
//     strict: true,
//     deprecationErrors: true,
//   }
// });

// async function run() {
//   try {
//     await client.connect();
//     const userCollection = client.db("MFSDb").collection("users");

//     // JWT Generation
//     app.post('/jwt', async (req, res) => {
//       const user = req.body;
//       const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1d" });
//       res.send({ token });
//     });

//     // Middleware to verify token
//     const verifyToken = (req, res, next) => {
//       const authHeader = req.headers.authorization;
//       if (!authHeader) {
//         return res.status(401).send({ message: 'forbidden access' });
//       }
//       const token = authHeader.split(' ')[1];
//       jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
//         if (err) {
//           return res.status(401).send({ message: 'forbidden access' });
//         }
//         req.decoded = decoded;
//         next();
//       });
//     };

//     // Middleware to verify admin
//     const verifyAdmin = async (req, res, next) => {
//       const email = req.decoded.email;
//       const user = await userCollection.findOne({ email: email });
//       if (!user || user.role !== 'admin') {
//         return res.status(403).send({ message: 'forbidden access' });
//       }
//       next();
//     };

//     // Middleware to verify agent
//     const verifyAgent = async (req, res, next) => {
//       const email = req.decoded.email;
//       const user = await userCollection.findOne({ email: email });
//       if (!user || user.role !== 'agent') {
//         return res.status(403).send({ message: 'forbidden access' });
//       }
//       next();
//     };

//     // Middleware to verify user
//     const verifyUser = async (req, res, next) => {
//       const email = req.decoded.email;
//       const user = await userCollection.findOne({ email: email });
//       if (!user || user.role !== 'user') {
//         return res.status(403).send({ message: 'forbidden access' });
//       }
//       next();
//     };

//     // User Registration
//     app.post('/register', async (req, res) => {
//       const { name, pin, mobileNumber, email, role = 'user' } = req.body;
//       const hashedPin = await bcrypt.hash(pin, 10);
//       const newUser = { name, pin: hashedPin, mobileNumber, email, role, status: 'pending', balance: 0 };
//       const result = await userCollection.insertOne(newUser);
//       res.status(201).send(result);
//     });

//     // User Login
//     app.post('/login', async (req, res) => {
//       const { email, mobileNumber, pin } = req.body;
//       const query = email ? { email } : { mobileNumber };
//       const user = await userCollection.findOne(query);
//       if (!user) {
//         return res.status(401).send({ message: 'Invalid credentials' });
//       }
//       const isPinValid = await bcrypt.compare(pin, user.pin);
//       if (!isPinValid) {
//         return res.status(401).send({ message: 'Invalid credentials' });
//       }
//       const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1d' });
//       res.send({ token, user });
//     });

//     // User Activation by Admin
//     app.patch('/users/activate/:id', verifyToken, verifyAdmin, async (req, res) => {
//       const id = req.params.id;
//       const filter = { _id: new ObjectId(id) };
//       const updateDoc = {
//         $set: {
//           status: 'active',
//           balance: 40 // credit bonus
//         }
//       };
//       const result = await userCollection.updateOne(filter, updateDoc);
//       res.send(result);
//     });

//     // Check if user is an admin
//     app.get('/users/admin/:email', verifyToken, async (req, res) => {
//       const email = req.params.email;
//       if (email !== req.decoded.email) {
//         return res.status(403).send({ message: 'unauthorized access' });
//       }
//       const user = await userCollection.findOne({ email });
//       const isAdmin = user && user.role === 'admin';
//       res.send({ admin: isAdmin });
//     });

//     // Get all users
//     app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
//       const users = await userCollection.find().toArray();
//       res.send(users);
//     });

//     // Make user admin
//     app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
//       const id = req.params.id;
//       const filter = { _id: new ObjectId(id) };
//       const updateDoc = {
//         $set: {
//           role: 'admin'
//         }
//       };
//       const result = await userCollection.updateOne(filter, updateDoc);
//       res.send(result);
//     });

//     // Make user agent
//     app.patch('/users/agent/:id', verifyToken, verifyAdmin, async (req, res) => {
//       const id = req.params.id;
//       const filter = { _id: new ObjectId(id) };
//       const updateDoc = {
//         $set: {
//           role: 'agent'
//         }
//       };
//       const result = await userCollection.updateOne(filter, updateDoc);
//       res.send(result);
//     });

//     // Delete user
//     app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
//       const id = req.params.id;
//       const result = await userCollection.deleteOne({ _id: new ObjectId(id) });
//       res.send(result);
//     });

//     console.log("Connected to MongoDB!");

//   } finally {
//     // Ensure proper cleanup if needed
//   }
// }

// run().catch(console.dir);

// app.get('/', (req, res) => {
//   res.send('MFS server is running');
// });

// app.listen(port, () => {
//   console.log(`MFS is sitting on port ${port}`);
// });

// const express = require('express');
// const cors = require('cors');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// require('dotenv').config();

// const app = express();
// const port = process.env.PORT || 5000;

// // Middleware
// app.use(cors());
// app.use(express.json());

// const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.5ynzghe.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// const client = new MongoClient(uri, {
//   serverApi: {
//     version: ServerApiVersion.v1,
//     strict: true,
//     deprecationErrors: true,
//   }
// });

// async function run() {
//   try {
//     await client.connect();
//     const userCollection = client.db("MFSDb").collection("users");

//     // JWT Generation
//     app.post('/jwt', async (req, res) => {
//       const user = req.body;
//       const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1d" });
//       res.send({ token });
//     });

//     // Middleware to verify token
//     const verifyToken = (req, res, next) => {
//       const authHeader = req.headers.authorization;
//       if (!authHeader) {
//         return res.status(401).send({ message: 'forbidden access' });
//       }
//       const token = authHeader.split(' ')[1];
//       jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
//         if (err) {
//           return res.status(401).send({ message: 'forbidden access' });
//         }
//         req.decoded = decoded;
//         next();
//       });
//     };

//     // Middleware to verify admin
//     const verifyAdmin = async (req, res, next) => {
//       const email = req.decoded.email;
//       const user = await userCollection.findOne({ email: email });
//       if (!user || user.role !== 'admin') {
//         return res.status(403).send({ message: 'forbidden access' });
//       }
//       next();
//     };

//     // User Registration
//     app.post('/register', async (req, res) => {
//       const { name, pin, mobileNumber, email } = req.body;
//       const hashedPin = await bcrypt.hash(pin, 10);
//       const newUser = { name, pin: hashedPin, mobileNumber, email, status: 'pending', balance: 0 };
//       const result = await userCollection.insertOne(newUser);
//       res.status(201).send(result);
//     });

//     // User Login
//     app.post('/login', async (req, res) => {
//       const { email, pin } = req.body;
//       const user = await userCollection.findOne({ email });
//       if (!user) {
//         return res.status(401).send({ message: 'Invalid credentials' });
//       }
//       const isPinValid = await bcrypt.compare(pin, user.pin);
//       if (!isPinValid) {
//         return res.status(401).send({ message: 'Invalid credentials' });
//       }
//       const token = jwt.sign({ userId: user._id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1d' });
//       res.send({ token, user });
//     });

//     // User Activation by Admin
//     app.patch('/users/activate/:id', verifyToken, verifyAdmin, async (req, res) => {
//       const id = req.params.id;
//       const filter = { _id: new ObjectId(id) };
//       const updateDoc = {
//         $set: {
//           status: 'active',
//           balance: 40 // credit bonus
//         }
//       };
//       const result = await userCollection.updateOne(filter, updateDoc);
//       res.send(result);
//     });

//     // Check if user is an admin
//     app.get('/users/admin/:email', verifyToken, async (req, res) => {
//       const email = req.params.email;
//       if (email !== req.decoded.email) {
//         return res.status(403).send({ message: 'unauthorized access' });
//       }
//       const user = await userCollection.findOne({ email });
//       const isAdmin = user && user.role === 'admin';
//       res.send({ admin: isAdmin });
//     });

//     // Get all users
//     app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
//       const users = await userCollection.find().toArray();
//       res.send(users);
//     });

//     // Make user admin
//     app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
//       const id = req.params.id;
//       const filter = { _id: new ObjectId(id) };
//       const updateDoc = {
//         $set: {
//           role: 'admin'
//         }
//       };
//       const result = await userCollection.updateOne(filter, updateDoc);
//       res.send(result);
//     });

//     // Delete user
//     app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
//       const id = req.params.id;
//       const result = await userCollection.deleteOne({ _id: new ObjectId(id) });
//       res.send(result);
//     });

//     console.log("Connected to MongoDB!");

//   } finally {
//     // Ensure proper cleanup if needed
//   }
// }

// run().catch(console.dir);

// app.get('/', (req, res) => {
//   res.send('MFS server is running');
// });

// app.listen(port, () => {
//   console.log(`MFS is sitting on port ${port}`);
// });
