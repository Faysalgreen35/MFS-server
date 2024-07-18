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

    // User Registration
    app.post('/register', async (req, res) => {
      const { name, pin, mobileNumber, email, role = 'user' } = req.body;
      const hashedPin = await bcrypt.hash(pin, 10);
      const newUser = { name, pin: hashedPin, mobileNumber, email, role, status: 'pending', balance: 0 };
      const result = await userCollection.insertOne(newUser);
      res.status(201).send(result);
    });

    // // User Login
    // app.post('/login', async (req, res) => {
    //   const { email, mobileNumber, pin } = req.body;
    //   const query = email ? { email } : { mobileNumber };
    //   const user = await userCollection.findOne(query);
    //   if (!user) {
    //     return res.status(401).send({ message: 'Invalid credentials' });
    //   }
    //   const isPinValid = await bcrypt.compare(pin, user.pin);
    //   if (!isPinValid) {
    //     return res.status(401).send({ message: 'Invalid credentials' });
    //   }
    //   const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1d' });
    //   res.send({ token, user });
    // });

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
      const result = await userCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // Send Money
    // app.post('/send', verifyToken, verifyRole('user'), async (req, res) => {
    //   const { recipientMobile, amount, pin } = req.body;
    //   if (amount < 50) return res.status(400).json({ message: 'Minimum transaction amount is 50 Taka' });

    //   try {
    //     const sender = await userCollection.findOne({ _id: new ObjectId(req.decoded.userId) });
    //     const recipient = await userCollection.findOne({ mobileNumber: recipientMobile });
    //     if (!recipient) return res.status(400).json({ message: 'Recipient not found' });

    //     const isMatch = await bcrypt.compare(pin, sender.pin);
    //     if (!isMatch) return res.status(400).json({ message: 'Invalid PIN' });

    //     let fee = 0;
    //     if (amount > 100) fee = 5;

    //     sender.balance -= (amount + fee);
    //     recipient.balance += amount;

    //     // Update balances
    //     await userCollection.updateOne({ _id: sender._id }, { $set: { balance: sender.balance } });
    //     await userCollection.updateOne({ _id: recipient._id }, { $set: { balance: recipient.balance } });

    //     // Record transaction
    //     const transaction = {
    //       senderId: sender._id,
    //       recipientId: recipient._id,
    //       amount,
    //       fee,
    //       type: 'send',
    //       timestamp: new Date()
    //     };
    //     await transactionCollection.insertOne(transaction);

    //     res.json({ message: 'Transaction successful' });
    //   } catch (error) {
    //     res.status(500).json({ message: error.message });
    //   }
    // });
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
  

    // Cash Out
    app.post('/cashout', verifyToken, verifyRole('user'), async (req, res) => {
      const { agentMobile, amount, pin } = req.body;
      if (amount < 50) return res.status(400).json({ message: 'Minimum transaction amount is 50 Taka' });

      try {
        const user = await userCollection.findOne({ _id: new ObjectId(req.decoded.userId) });
        const agent = await userCollection.findOne({ mobileNumber: agentMobile });
        if (!agent) return res.status(400).json({ message: 'Agent not found' });

        const isMatch = await bcrypt.compare(pin, user.pin);
        if (!isMatch) return res.status(400).json({ message: 'Invalid PIN' });

        const fee = amount * 0.015;

        user.balance -= (amount + fee);
        agent.balance += amount + fee;

        // Update balances
        await userCollection.updateOne({ _id: user._id }, { $set: { balance: user.balance } });
        await userCollection.updateOne({ _id: agent._id }, { $set: { balance: agent.balance } });

        // Record transaction
        const transaction = {
          userId: user._id,
          agentId: agent._id,
          amount,
          fee,
          type: 'cashout',
          timestamp: new Date()
        };
        await transactionCollection.insertOne(transaction);

        res.json({ message: 'Cash out successful' });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Get Transaction History for User
    app.get('/transactions', verifyToken, async (req, res) => {
      try {
        const transactions = await transactionCollection.find({ userId: new ObjectId(req.decoded.userId) }).toArray();
        res.json(transactions);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

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
 